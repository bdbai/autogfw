use {
    ipnetwork::IpNetwork,
    libc::{
        c_int, c_void, setsockopt, strerror, ETH_P_IP, ETH_P_IPV6, IPPROTO_IPV6, SOL_SOCKET,
        SO_BINDTODEVICE,
    },
    pnet::{
        datalink::interfaces,
        packet::{
            ip::IpNextHeaderProtocol,
            ipv4::{checksum, Ipv4Packet, MutableIpv4Packet},
            ipv6::{Ipv6Packet, MutableIpv6Packet},
            tcp::{self, MutableTcpPacket},
            udp::{self, MutableUdpPacket},
            MutablePacket, Packet,
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

const TCP: u8 = 0x06;
const UDP: u8 = 0x11;
const IPV6_HDRINCL: c_int = 36;
pub trait IpPacket {
    fn ether_type() -> u16;
    fn get_source(&self) -> IpAddr;
    fn get_destination(&self) -> IpAddr;
}

impl<'a> IpPacket for Ipv4Packet<'a> {
    fn ether_type() -> u16 {
        ETH_P_IP as u16
    }

    fn get_source(&self) -> IpAddr {
        self.get_source().into()
    }

    fn get_destination(&self) -> IpAddr {
        self.get_destination().into()
    }
}

impl<'a> IpPacket for Ipv6Packet<'a> {
    fn ether_type() -> u16 {
        ETH_P_IPV6 as u16
    }

    fn get_source(&self) -> IpAddr {
        self.get_source().into()
    }

    fn get_destination(&self) -> IpAddr {
        self.get_destination().into()
    }
}

pub struct PacketSender {
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    send_channel_v4: Option<TransportSender>,
    send_channel_v6: Option<TransportSender>,
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
            send_channel_v4: None,
            send_channel_v6: None,
        };

        // IPv4 outbound
        let (tx, _rx) =
            transport_channel(2048, TransportChannelType::Layer3(IpNextHeaderProtocol(4))) // IPv4 only
                .expect("Cannot open send channel");
        let socket = tx.socket.clone();
        unsafe { Self::set_sockopts(netif_name, socket.fd, false)? }
        ret.send_channel_v4 = Some(tx);

        // IPv6 outbound
        let (tx, _rx) = transport_channel(
            2048,
            TransportChannelType::Layer4(TransportProtocol::Ipv6(IpNextHeaderProtocol(41))),
        )
        .expect("Cannot open send channel");
        let socket = tx.socket.clone();
        unsafe { Self::set_sockopts(netif_name, socket.fd, true)? }
        ret.send_channel_v6 = Some(tx);

        Ok(ret)
    }
    pub fn send_v4<'a, T: IpPacket + Packet + 'a>(
        &mut self,
        main_out_packet: T,
    ) -> Result<(), Error> {
        let ipv4_addr = self.ipv4_addr;
        let mut new_ip_packet =
            MutableIpv4Packet::owned(main_out_packet.packet().to_vec()).unwrap();
        new_ip_packet.set_source(ipv4_addr.unwrap());
        let checksum = checksum(&new_ip_packet.to_immutable());
        new_ip_packet.set_checksum(checksum);
        Self::recalculate_ipv4_l4_checksum(&mut new_ip_packet);
        let dest = IpAddr::V4(new_ip_packet.get_destination());
        self.send_channel_v4
            .as_mut()
            .unwrap()
            .send_to(new_ip_packet, dest)
            .map(|_| ())
    }
    pub fn send_v6<'a, T: IpPacket + Packet + 'a>(
        &mut self,
        main_out_packet: T,
    ) -> Result<(), Error> {
        let ipv4_addr = self.ipv6_addr;
        let mut new_ip_packet =
            MutableIpv6Packet::owned(main_out_packet.packet().to_vec()).unwrap();
        new_ip_packet.set_source(ipv4_addr.unwrap());
        Self::recalculate_ipv6_l4_checksum(&mut new_ip_packet);
        let dest = IpAddr::V6(new_ip_packet.get_destination());
        self.send_channel_v6
            .as_mut()
            .unwrap()
            .send_to(new_ip_packet, dest)
            .map(|_| ())
    }
}

pub trait SendChannel<'a, T: IpPacket + Packet + 'a> {
    fn send_packet(&mut self, main_out_packet: T) -> Result<(), Error>;
}

impl<'a> SendChannel<'a, Ipv4Packet<'a>> for PacketSender {
    fn send_packet(&mut self, main_out_packet: Ipv4Packet) -> Result<(), Error> {
        self.send_v4(main_out_packet)
    }
}

impl<'a> SendChannel<'a, Ipv6Packet<'a>> for PacketSender {
    fn send_packet(&mut self, main_out_packet: Ipv6Packet) -> Result<(), Error> {
        self.send_v6(main_out_packet)
    }
}
