use std::{
    fmt::{Display, Formatter, Result},
    hash::Hash,
    net::IpAddr,
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
    pub fn src_from_packet(packet: &[u8]) -> Self {
        match (packet[12], packet[13]) {
            (0x08, 0x00) => Self::v4_from_bytes(&packet[26..30]),
            (0x86, 0xDD) => Self::v6_from_bytes(&packet[22..38]),
            (b1, b2) => panic!("Unknown packet type: {} {}", b1, b2),
        }
    }
    pub fn dst_from_packet(packet: &[u8]) -> Self {
        match (packet[12], packet[13]) {
            (0x08, 0x00) => Self::v4_from_bytes(&packet[30..34]),
            (0x86, 0xDD) => Self::v6_from_bytes(&packet[38..54]),
            (b1, b2) => panic!("Unknown packet type: {} {}", b1, b2),
        }
    }
}
