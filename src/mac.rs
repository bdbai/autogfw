use {
    crate::LIB,
    pnet::datalink::MacAddr,
    rawsock::traits::Library,
    std::{
        fs::File,
        io::{BufRead, BufReader},
        net::{IpAddr, Ipv4Addr, Ipv6Addr},
        str::FromStr,
    },
};

#[derive(Debug, Clone)]
struct ArpEntry {
    ip_addr: IpAddr,
    // hw_type: u32,
    // flags: u32,
    hw_addr: MacAddr,
    // mask: String,
    // device: String
}

fn get_arp_entries(netif_name: &str) -> Vec<ArpEntry> {
    let file = File::open("/proc/net/arp").expect("Cannot open arp file");
    let mut reader = BufReader::new(file);
    let mut buf = String::with_capacity(100);
    reader.read_line(&mut buf).unwrap();
    buf.clear();
    let mut ret = vec![];
    while let Ok(size) = reader.read_line(&mut buf) {
        if size == 0 {
            break;
        }
        let fields: Vec<&str> = buf.split_whitespace().collect();
        assert_eq!(
            fields.len(),
            6,
            "An ARP entry should have at least 5 fields"
        );
        if (fields[2] == "0x2" || fields[2] == "0x6") && fields[5] == netif_name {
            ret.push(ArpEntry {
                ip_addr: Ipv4Addr::from_str(fields[0])
                    .map(|ipv4| IpAddr::V4(ipv4))
                    .unwrap_or_else(|_| IpAddr::V6(Ipv6Addr::from_str(fields[0]).unwrap())),
                hw_addr: MacAddr::from_str(fields[3]).unwrap(),
            });
        }
        buf.clear();
    }
    ret
}

pub fn get_dst_address_by_netif_name(netif_name: &str) -> MacAddr {
    let netif = LIB
        .get()
        .unwrap()
        .all_interfaces()
        .unwrap()
        .into_iter()
        .find(|netif| netif.name == netif_name)
        .unwrap();
    let addresses = netif.addresses.unwrap();
    let arp_entries = get_arp_entries(netif_name);
    arp_entries
        .into_iter()
        .find(|arp| {
            addresses
                .iter()
                .any(|addr| addr.address.map_or(false, |addr| addr.ip() != arp.ip_addr))
        })
        .unwrap()
        .hw_addr
}
