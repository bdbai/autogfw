use {
    ipnetwork::IpNetwork,
    pnet::{
        datalink::{channel, interfaces, Channel, DataLinkSender, MacAddr, NetworkInterface},
        packet::{
            ethernet::{EtherType, EthernetPacket, MutableEthernetPacket},
            ipv4::{checksum, MutableIpv4Packet},
            ipv6::MutableIpv6Packet,
            MutablePacket,
        },
    },
    std::{
        io::Error,
        net::{Ipv4Addr, Ipv6Addr},
    },
};

const ETHER_TYPE_IPV4: u16 = 0x0800;
const ETHER_TYPE_IPV6: u16 = 0x86DD;

pub struct PacketSender {
    netif: NetworkInterface,
    mac: MacAddr,
    ipv4_addr: Option<Ipv4Addr>,
    ipv6_addr: Option<Ipv6Addr>,
    channel: Option<Box<dyn DataLinkSender>>,
}

impl PacketSender {
    pub fn open(netif_name: &str) -> Result<Self, String> {
        let netif = interfaces()
            .into_iter()
            .find(|netif| netif.name == netif_name)
            .ok_or_else(|| "Cannot find network interface ".to_string() + netif_name)?;
        let mac = netif
            .mac
            .ok_or_else(|| "Cannot find MAC address for ".to_string() + netif_name)?;
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
            mac,
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
        let mac = self.mac;
        let ether_packet = EthernetPacket::new(ether_packet).unwrap();
        let ipv4_addr = self.ipv4_addr;
        let ipv6_addr = self.ipv6_addr;
        self.channel
            .as_mut()
            .unwrap()
            .build_and_send(1, size, &mut |new_packet| {
                let mut new_ether_packet = MutableEthernetPacket::new(new_packet).unwrap();
                new_ether_packet.clone_from(&ether_packet);
                new_ether_packet.set_destination(mac);
                match (new_ether_packet.get_ethertype(), ipv4_addr, ipv6_addr) {
                    (EtherType(ETHER_TYPE_IPV4), Some(ipv4_addr), _) => {
                        // IPV4
                        let mut new_ip_packet =
                            MutableIpv4Packet::new(&mut new_packet[14..]).unwrap();
                        new_ip_packet.set_source(ipv4_addr);
                        let checksum = checksum(&new_ip_packet.to_immutable());
                        new_ip_packet.set_checksum(checksum);
                    }
                    (EtherType(ETHER_TYPE_IPV6), _, Some(ipv6_addr)) => {
                        // IPV6
                        let mut new_ip_packet =
                            MutableIpv6Packet::new(&mut new_packet[14..]).unwrap();
                        new_ip_packet.set_source(ipv6_addr);
                    }
                    _ => {}
                }
            })
            .unwrap()
    }
}
