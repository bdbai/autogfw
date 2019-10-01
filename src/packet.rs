use {
    crate::mac::get_dst_address_by_netif_name,
    ipnetwork::IpNetwork,
    pnet::{
        datalink::{channel, interfaces, Channel, DataLinkSender, MacAddr, NetworkInterface},
        packet::{
            ethernet::{EtherType, EthernetPacket, MutableEthernetPacket},
            ip::IpNextHeaderProtocol,
            ipv4::{checksum, MutableIpv4Packet},
            ipv6::MutableIpv6Packet,
            tcp::{self, MutableTcpPacket},
            udp::{self, MutableUdpPacket},
            MutablePacket, Packet,
        },
    },
    std::{
        io::Error,
        net::{Ipv4Addr, Ipv6Addr},
    },
};

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;
const TCP: u8 = 0x06;
const UDP: u8 = 0x11;
pub const IPV4_VERSION: u8 = 0x45;
pub const IPV6_VERSION: u8 = 0x60; // higher 4 bits only

pub struct PacketSender {
    netif: NetworkInterface,
    src_mac: Option<MacAddr>,
    dst_mac: Option<MacAddr>,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    channel: Option<Box<dyn DataLinkSender>>,
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
    pub fn open(netif_name: &str) -> Result<Self, String> {
        let netif = interfaces()
            .into_iter()
            .find(|netif| netif.name == netif_name)
            .ok_or_else(|| "Cannot find network interface ".to_string() + netif_name)?;
        let src_mac = netif.mac;
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
            netif,
            src_mac,
            dst_mac: get_dst_address_by_netif_name(netif_name),
            ipv4_addr,
            ipv6_addr,
            channel: None,
        };
        let chan = match channel(&ret.netif, Default::default()).unwrap() {
            Channel::Ethernet(tx, _rx) => tx,
            _ => panic!("Unknown channel type"),
        };
        ret.channel = Some(chan);
        Ok(ret)
    }
    pub fn send(&mut self, ether_packet: &[u8]) -> Result<(), Error> {
        let size = ether_packet.len();
        if size < EthernetPacket::minimum_packet_size() {
            return Ok(());
        }
        let src_mac = self.src_mac;
        let dst_mac = self.dst_mac;
        let ether_packet = EthernetPacket::new(ether_packet).unwrap();
        let ipv4_addr = self.ipv4_addr;
        let ipv6_addr = self.ipv6_addr;
        self.channel
            .as_mut()
            .unwrap()
            .build_and_send(1, src_mac.map_or(size - 14, |_| size), &mut |new_packet| {
                let mut packet = new_packet;
                let ether_type = if let (Some(src_mac), Some(dst_mac)) = (src_mac, dst_mac) {
                    let mut new_ether_packet = MutableEthernetPacket::new(packet).unwrap();
                    new_ether_packet.clone_from(&ether_packet);
                    new_ether_packet.set_source(src_mac);
                    new_ether_packet.set_destination(dst_mac);
                    let ether_type = new_ether_packet.get_ethertype();
                    packet = &mut packet[14..];
                    ether_type
                } else {
                    packet.copy_from_slice(ether_packet.payload());
                    match packet[0] {
                        IPV4_VERSION => EtherType(ETHER_TYPE_IPV4),
                        byte if byte & 0xF0 == IPV6_VERSION => EtherType(ETHER_TYPE_IPV6),
                        _ => return,
                    }
                };
                match (ether_type, ipv4_addr, ipv6_addr) {
                    (EtherType(ETHER_TYPE_IPV4), Some(ipv4_addr), _) => {
                        // IPV4
                        let mut new_ip_packet = MutableIpv4Packet::new(packet).unwrap();
                        new_ip_packet.set_source(ipv4_addr);
                        let checksum = checksum(&new_ip_packet.to_immutable());
                        new_ip_packet.set_checksum(checksum);
                        Self::recalculate_ipv4_l4_checksum(&mut new_ip_packet);
                    }
                    (EtherType(ETHER_TYPE_IPV6), _, Some(ipv6_addr)) => {
                        // IPV6
                        let mut new_ip_packet = MutableIpv6Packet::new(packet).unwrap();
                        new_ip_packet.set_source(ipv6_addr);
                        Self::recalculate_ipv6_l4_checksum(&mut new_ip_packet);
                    }
                    _ => {}
                }
            })
            .unwrap()
    }

    pub fn update_dst_hw_from_packet(&mut self, ether_packet: &[u8]) {
        EthernetPacket::new(ether_packet).map(|ether_packet| {
            self.dst_mac = Some(ether_packet.get_source());
        });
    }
}
