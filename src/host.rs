use {
    crate::packet::{IPV4_VERSION, IPV6_VERSION},
    log::error,
    rawsock::DataLink,
    std::{
        fmt::{Display, Formatter, Result},
        hash::Hash,
        net::IpAddr,
    },
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct Host {
    pub addr: IpAddr,
}

impl Display for Host {
    fn fmt(&self, f: &mut Formatter) -> Result {
        self.addr.fmt(f)
    }
}

impl Host {
    fn v4_from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 4);
        let addr = unsafe { (*(bytes.as_ptr() as *const u32)) };
        Self {
            addr: IpAddr::V4(u32::from_be(addr).into()),
        }
    }
    fn v6_from_bytes(bytes: &[u8]) -> Self {
        assert_eq!(bytes.len(), 16);
        let addr = unsafe { *(bytes.as_ptr() as *const [u8; 16]) };
        Self {
            addr: IpAddr::V6(addr.into()),
        }
    }
    pub fn src_from_packet(packet: &[u8], data_link: DataLink) -> Option<Self> {
        match data_link {
            DataLink::Ethernet => match (packet[12], packet[13]) {
                (0x08, 0x00) => Some(Self::v4_from_bytes(&packet[26..30])),
                (0x86, 0xDD) => Some(Self::v6_from_bytes(&packet[22..38])),
                (b1, b2) => (error!("Unknown ether type: {} {}", b1, b2), None).1,
            },
            DataLink::RawIp => match packet[0] {
                IPV4_VERSION => Some(Self::v4_from_bytes(&packet[12..16])),
                byte if byte & 0xF0 == IPV6_VERSION => Some(Self::v6_from_bytes(&packet[8..24])),
                byte => (error!("Unknown packet type: {}", byte), None).1,
            },
            DataLink::Other => (error!("Unknown data link type"), None).1,
        }
    }
    pub fn dst_from_packet(packet: &[u8], data_link: DataLink) -> Option<Self> {
        match data_link {
            DataLink::Ethernet => match (packet[12], packet[13]) {
                (0x08, 0x00) => Some(Self::v4_from_bytes(&packet[30..34])),
                (0x86, 0xDD) => Some(Self::v6_from_bytes(&packet[38..54])),
                (b1, b2) => (error!("Unknown packet type: {} {}", b1, b2), None).1,
            },
            DataLink::RawIp => match packet[0] {
                IPV4_VERSION => Some(Self::v4_from_bytes(&packet[16..20])),
                byte if byte & 0xF0 == IPV6_VERSION => Some(Self::v6_from_bytes(&packet[24..40])),
                byte => (error!("Unknown packet type: {}", byte), None).1,
            },
            DataLink::Other => (error!("Unknown data link type"), None).1,
        }
    }
}
