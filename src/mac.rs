use {
    pnet::datalink::MacAddr,
    std::{process::Command, str::FromStr},
};

fn get_default_dest(netif_name: &str) -> Option<String> {
    let output = Command::new("ip")
        .arg("route")
        .arg("show")
        .arg("dev")
        .arg(netif_name)
        .output()
        .expect("Cannot execute ip command");
    let output = String::from_utf8(output.stdout).unwrap();
    output.lines().find_map(|line| {
        if line.starts_with("default") {
            let fields: Vec<&str> = line.split_whitespace().collect();
            Some(fields[2].to_owned())
        } else {
            None
        }
    })
}

fn get_arp_entry(ip: &str) -> Option<MacAddr> {
    let output = Command::new("ip")
        .arg("neigh")
        .arg("show")
        .arg("to")
        .arg(ip)
        .output()
        .expect("Cannot execute ip command");
    let output = String::from_utf8(output.stdout).unwrap();
    output.lines().find_map(|line| {
        let fields: Vec<&str> = line.split_whitespace().collect();
        fields
            .get(4)
            .map(|s| MacAddr::from_str(s).expect("Invalid MAC address"))
    })
}

pub fn get_dst_address_by_netif_name(netif_name: &str) -> Option<MacAddr> {
    let dest = get_default_dest(netif_name)?;
    get_arp_entry(dest.as_str())
}
