use {
    ipnetwork::IpNetwork,
    libc::{c_int, c_void, setsockopt, strerror, IPPROTO_IPV6, SOL_SOCKET, SO_BINDTODEVICE},
    log::warn,
    pnet::{
        datalink::interfaces,
        packet::{
            ethernet::{EtherType, MutableEthernetPacket},
            ip::IpNextHeaderProtocol,
            ipv4::{checksum, MutableIpv4Packet},
            ipv6::MutableIpv6Packet,
            tcp::{self, MutableTcpPacket},
            udp::{self, MutableUdpPacket},
            MutablePacket,
        },
        transport::{transport_channel, TransportChannelType, TransportProtocol, TransportSender},
    },
    std::{
        convert::TryInto,
        ffi::{CStr, CString},
        io::Error,
        mem::size_of,
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
    },
};

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const TCP: u8 = 0x06;
const UDP: u8 = 0x11;
const IPV6_HDRINCL: c_int = 36;
pub const IPV4_VERSION: u8 = 0x45;
pub const IPV6_VERSION: u8 = 0x60; // higher 4 bits only

pub struct PacketSender {
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    channel_v4: Option<TransportSender>,
    channel_v6: Option<TransportSender>,
}

impl PacketSender {
    fn recalculate_ipv4_l4_checksum(packet: &mut MutableIpv4Packet) {
        match packet.get_next_level_protocol() {
            IpNextHeaderProtocol(TCP) => {
                let (src_addr, dst_addr) = (packet.get_source(), packet.get_destination());
                let mut tcp_packet = MutableTcpPacket::new(packet.payload_mut()).unwrap();
                let checksum = tcp::ipv4_checksum(&tcp_packet.to_immutable(), &src_addr, &dst_addr);
                tcp_packet.set_checksum(checksum);
            }
            IpNextHeaderProtocol(UDP) => {
                let (src_addr, dst_addr) = (packet.get_source(), packet.get_destination());
                let mut udp_packet = MutableUdpPacket::new(packet.payload_mut()).unwrap();
                let checksum = udp::ipv4_checksum(&udp_packet.to_immutable(), &src_addr, &dst_addr);
                udp_packet.set_checksum(checksum);
            }
            _ => {}
        }
    }
    fn recalculate_ipv6_l4_checksum(packet: &mut MutableIpv6Packet) {
        match packet.get_next_header() {
            IpNextHeaderProtocol(TCP) => {
                let (src_addr, dst_addr) = (packet.get_source(), packet.get_destination());
                let mut tcp_packet = MutableTcpPacket::new(packet.payload_mut()).unwrap();
                let checksum = tcp::ipv6_checksum(&tcp_packet.to_immutable(), &src_addr, &dst_addr);
                tcp_packet.set_checksum(checksum);
            }
            IpNextHeaderProtocol(UDP) => {
                let (src_addr, dst_addr) = (packet.get_source(), packet.get_destination());
                let mut udp_packet = MutableUdpPacket::new(packet.payload_mut()).unwrap();
                let checksum = udp::ipv6_checksum(&udp_packet.to_immutable(), &src_addr, &dst_addr);
                udp_packet.set_checksum(checksum);
            }
            _ => {}
        }
    }
    unsafe fn check_errno(errno: c_int) -> Result<(), String> {
        if errno != 0 {
            return Err(
                CStr::into_c_string(Box::from(CStr::from_ptr(strerror(errno))))
                    .into_string()
                    .unwrap(),
            );
        }
        Ok(())
    }
    unsafe fn set_sockopts(netif: &str, socket_fd: c_int, is_ipv6: bool) -> Result<(), String> {
        let netif_str = CString::new(netif).unwrap();
        Self::check_errno(setsockopt(
            socket_fd,
            SOL_SOCKET,
            SO_BINDTODEVICE,
            netif_str.as_ptr() as *const c_void,
            netif_str.as_bytes().len().try_into().unwrap(),
        ))?;
        if is_ipv6 {
            let opt: c_int = 1;
            Self::check_errno(setsockopt(
                socket_fd,
                IPPROTO_IPV6,
                IPV6_HDRINCL,
                &opt as *const c_int as *const c_void,
                size_of::<c_int>().try_into().unwrap(),
            ))?
        }
        Ok(())
    }
    pub fn open(netif_name: &str) -> Result<Self, String> {
        let netif = interfaces()
            .into_iter()
            .find(|netif| netif.name == netif_name)
            .ok_or_else(|| "Cannot find network interface ".to_string() + netif_name)?;
        let ipv4_addr = netif.ips.iter().find_map(|ip| {
            if let IpNetwork::V4(v4) = ip {
                Some(v4.ip())
            } else {
                None
            }
        });
        let ipv6_addr = netif.ips.iter().find_map(|ip| {
            if let IpNetwork::V6(v6) = ip {
                Some(v6.ip())
            } else {
                None
            }
        });
        let mut ret = Self {
            ipv4_addr,
            ipv6_addr,
            channel_v4: None,
            channel_v6: None,
        };
        let (tx, _rx) =
            transport_channel(2048, TransportChannelType::Layer3(IpNextHeaderProtocol(4))) // IPv4 only
                .expect("Cannot open send channel");
        let socket = tx.socket.clone();
        unsafe { Self::set_sockopts(netif_name, socket.fd, false)? }
        ret.channel_v4 = Some(tx);
        let (tx, _rx) = transport_channel(
            2048,
            TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocol(4))),
        )
        .expect("Cannot open send channel");
        let socket = tx.socket.clone();
        unsafe { Self::set_sockopts(netif_name, socket.fd, true)? }
        Ok(ret)
    }
    pub fn send(&mut self, ether_packet: &[u8]) -> Result<(), Error> {
        let size = ether_packet.len();
        if size < 20 {
            return Ok(());
        }
        let ipv4_addr = self.ipv4_addr;
        let ipv6_addr = self.ipv6_addr;
        let mut ether_packet = ether_packet.to_vec();
        let mut ether_packet = MutableEthernetPacket::new(&mut ether_packet).unwrap();
        match ether_packet.get_ethertype() {
            EtherType(ETHER_TYPE_IPV4) => {
                let mut new_ip_packet = MutableIpv4Packet::new(ether_packet.payload_mut()).unwrap();
                new_ip_packet.set_source(ipv4_addr.unwrap());
                let checksum = checksum(&new_ip_packet.to_immutable());
                new_ip_packet.set_checksum(checksum);
                Self::recalculate_ipv4_l4_checksum(&mut new_ip_packet);
                let dest = IpAddr::V4(new_ip_packet.get_destination());
                self.channel_v4
                    .as_mut()
                    .unwrap()
                    .send_to(new_ip_packet, dest)
                    .map(|_| ())
            }
            EtherType(ETHER_TYPE_IPV6) => {
                let mut new_ip_packet = MutableIpv6Packet::new(ether_packet.payload_mut()).unwrap();
                new_ip_packet.set_source(ipv6_addr.unwrap());
                Self::recalculate_ipv6_l4_checksum(&mut new_ip_packet);
                let dest = IpAddr::V6(new_ip_packet.get_destination());
                self.channel_v6
                    .as_mut()
                    .unwrap()
                    .send_to(new_ip_packet, dest)
                    .map(|_| ())
            }
            _ => (warn!("Unknown ether type to send"), Ok(())).1,
        }
    }
}
