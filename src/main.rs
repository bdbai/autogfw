mod packet;
mod state;

use {
    env_logger::{self, Env},
    libc::sockaddr_ll,
    log::{debug, error, info},
    once_cell::sync::OnceCell,
    packet::{IpPacket, PacketSender, SendChannel},
    parking_lot::{Mutex, RwLock},
    pnet::{
        datalink::linux::{channel as datalink_channel, Config},
        datalink::{interfaces, Channel, ChannelType, NetworkInterface},
        packet::{ipv4::Ipv4Packet, ipv6::Ipv6Packet, Packet, PacketSize},
    },
    state::State,
    std::{
        cell::RefCell,
        collections::HashMap,
        mem::zeroed,
        net::IpAddr,
        process::{exit, Command},
        rc::Rc,
        str::from_utf8,
        sync::mpsc::{channel, Receiver, Sender},
        thread,
        time::{Duration, Instant},
    },
    structopt::StructOpt,
};

#[derive(StructOpt, Debug)]
struct Cli {
    /// The main interface to inspect
    #[structopt(short = "m", long = "main-netif")]
    main_netif: String,
    /// The side interface (usually VPN) to inspect
    #[structopt(short = "s", long = "side-netif")]
    side_netif: String,
    /// Timeout (in seconds)
    #[structopt(short = "t", long = "timeout", default_value = "2")]
    timeout: u64,
    /// Do not process inbound packets from main interface for debug purposes
    #[structopt(short = "k", long = "skip-main")]
    skip_main_inbound: bool,
    /// The arguments passed to  `ip route replace`.
    /// Will be appended to `ip route replace $ip_addr`.
    /// If not specified, routes will not be changed.
    #[structopt(short = "c", long = "add-args")]
    route_add_arguments: Option<Vec<String>>,
}

type Host = IpAddr;
type StateArgs = (Host, state::State);
type TimerArgs = (Host, Instant);

const PACKET_HOST: u8 = 0;
const PACKET_OUTGOING: u8 = 4;
static OPT: OnceCell<Cli> = OnceCell::new();
static STATES: OnceCell<RwLock<HashMap<Host, Mutex<state::State>>>> = OnceCell::new();
static SIDE_SENDER: OnceCell<Mutex<PacketSender>> = OnceCell::new();

fn handle_netif_packets(
    netif: &NetworkInterface,
    mut on_inbound_v4_packet: impl FnMut(&[u8]),
    mut on_inbound_v6_packet: impl FnMut(&[u8]),
    mut on_outbound_v4_packet: impl FnMut(&[u8]),
    mut on_outbound_v6_packet: impl FnMut(&[u8]),
) {
    let sockaddr = Rc::new(RefCell::new(unsafe { zeroed() }));
    let mut rx = match datalink_channel(
        netif,
        Config {
            channel_type: ChannelType::Layer3(3),
            recv_sockaddr_storage: Some(sockaddr.clone()),
            ..Default::default()
        },
    )
    .unwrap()
    {
        Channel::Ethernet(_tx, rx) => rx,
        _ => panic!("Unhandled ether type from pnet"),
    };
    loop {
        let packet = if let Ok(packet) = rx.next() {
            packet
        } else {
            continue;
        };

        // See https://linux.die.net/man/7/packet Address types
        let pkttype = unsafe { *(sockaddr.as_ptr() as *const sockaddr_ll) }.sll_pkttype;
        let header_half = packet[0] >> 4;
        match (pkttype, header_half) {
            (PACKET_HOST, 4) => on_inbound_v4_packet(packet),
            (PACKET_HOST, 6) => on_inbound_v6_packet(packet),
            (PACKET_OUTGOING, 4) => on_outbound_v4_packet(packet),
            (PACKET_OUTGOING, 6) => on_outbound_v6_packet(packet),
            _ => {}
        };
    }
}

fn handle_main_outbound_packet<'a, T: IpPacket + Packet + PacketSize + 'a>(
    packet: T,
    state_tx: &Sender<StateArgs>,
    timer_tx: &Sender<TimerArgs>,
) where
    PacketSender: packet::SendChannel<'a, T>,
{
    let host = packet.get_destination();
    let states = STATES.get().unwrap().read();
    if states.get(&host).is_none() {
        state_tx.send((host, State::Pending)).unwrap();
        match SIDE_SENDER.get().unwrap().lock().send_packet(packet) {
            Ok(()) => {
                timer_tx.send((host, Instant::now())).unwrap();
            }
            Err(e) => {
                state_tx.send((host, State::TimedOut)).unwrap();
                error!("Error sending test packet: {}", e);
            }
        }
    }
}

fn handle_main_inbound_packet<'a>(packet: impl IpPacket + 'a, state_tx: &Sender<StateArgs>) {
    if OPT.get().map(|o| o.skip_main_inbound).unwrap() {
        return;
    }
    let host = packet.get_source();
    let states = STATES.get().unwrap().read();
    if states
        .get(&host)
        .map_or(true, |state| *state.lock() != State::KnownDirect)
    {
        state_tx.send((host, State::KnownDirect)).unwrap();
    }
}

fn handle_side_inbound_packets<'a>(packet: impl IpPacket + 'a, state_tx: &Sender<StateArgs>) {
    let host = packet.get_source();
    let states = STATES.get().unwrap().read();
    if let Some(state) = states.get(&host) {
        if State::Pending == *state.lock() {
            state_tx.send((host, State::KnownProxy)).unwrap();
        }
    }
}

fn state_handler(rx: Receiver<StateArgs>) {
    let opts = &OPT.get().unwrap();
    let add_args = &opts.route_add_arguments;
    for (host, next_state) in rx.into_iter() {
        let mut states = STATES.get().unwrap().write();
        if let Some(state) = states.get(&host).map(|s| *s.lock()) {
            match (state, next_state) {
                (_, State::Pending) => {
                    continue;
                }
                (old, new) if old == new => {
                    continue;
                }
                (State::KnownDirect, State::KnownProxy) => {
                    continue;
                }
                (State::KnownDirect, State::TimedOut) | (State::KnownProxy, State::TimedOut) => {
                    continue;
                }
                _ => {}
            }
        }
        debug!(
            "State change: host = {}, state = {}",
            host,
            next_state.clone()
        );
        states
            .entry(host)
            .and_modify(|s| *s.lock() = next_state)
            .or_insert_with(|| Mutex::from(next_state));
        match (add_args, next_state) {
            (Some(add_args), State::KnownProxy) => {
                let output = Command::new("ip")
                    .arg("route")
                    .arg("replace")
                    .arg(host.to_string())
                    .args(add_args)
                    .output()
                    .expect("Error executing ip route replace command");
                if output.status.success() {
                    info!("Route replaced: host = {}", host);
                } else {
                    error!(
                        "Error replacing route: host = {}, stdout = {}, stderr = {}",
                        host,
                        from_utf8(&output.stdout).unwrap().trim(),
                        from_utf8(&output.stderr).unwrap().trim()
                    )
                }
            }
            (Some(_), State::KnownDirect) | (Some(_), State::TimedOut) => {
                let output = Command::new("ip")
                    .arg("route")
                    .arg("delete")
                    .arg(host.to_string())
                    .output()
                    .expect("Error executing ip route delete command");
                if output.status.success() {
                    info!("Route deleted: host = {}", host);
                } else {
                    let stderr = from_utf8(&output.stderr).unwrap().trim();
                    if stderr.ends_with("No such process") {
                        debug!("No such route: host = {}", host);
                    } else {
                        error!(
                            "Error deleting route: host = {}, stdout = {}, stderr = {}",
                            host,
                            from_utf8(&output.stdout).unwrap().trim(),
                            stderr
                        );
                    }
                }
            }
            _ => {}
        }
    }
}

fn timer_handler(state_tx: &Sender<StateArgs>, timer_rx: Receiver<TimerArgs>) {
    let timeout = Duration::from_secs(OPT.get().unwrap().timeout as u64);
    for (port, fire_time) in timer_rx.into_iter() {
        timeout
            .checked_sub(Instant::now().duration_since(fire_time))
            .map(thread::sleep)
            .unwrap_or(());
        let states = STATES.get().unwrap().read();
        if let Some(state) = states.get(&port) {
            if State::Pending == *state.lock() {
                state_tx.send((port, State::TimedOut)).unwrap()
            }
        }
    }
}

fn main() {
    env_logger::init_from_env(Env::default().default_filter_or("info"));
    let opts = Cli::from_args();
    if opts.main_netif == opts.side_netif {
        error!("Main interface cannot be the same as the side interface");
        exit(1);
    }
    let skip_main_inbound = opts.skip_main_inbound;
    STATES
        .set(RwLock::new(HashMap::with_capacity(1024)))
        .unwrap();

    let interfaces = interfaces();
    let main_netif = interfaces
        .iter()
        .find(|i| i.name == opts.main_netif)
        .expect("No such main interface")
        .clone();
    let side_netif = interfaces
        .iter()
        .find(|i| i.name == opts.side_netif)
        .expect("No such side interface")
        .clone();
    SIDE_SENDER
        .set(Mutex::new(PacketSender::open(&opts.side_netif).unwrap()))
        .map_err(|_| ())
        .unwrap();
    OPT.set(opts).map_err(|_| ()).unwrap();
    let (state_tx, state_rx) = channel();
    let (timer_tx, timer_rx) = channel();

    let main_netif_thread = {
        let netif = main_netif.clone();
        let state_tx = state_tx.clone();
        let timer_tx = timer_tx.clone();
        thread::spawn(move || {
            if skip_main_inbound {
                handle_netif_packets(
                    &netif,
                    |_| {},
                    |_| {},
                    |packet| {
                        Ipv4Packet::new(packet)
                            .map(|p| handle_main_outbound_packet(p, &state_tx, &timer_tx));
                    },
                    |packet| {
                        Ipv6Packet::new(packet)
                            .map(|p| handle_main_outbound_packet(p, &state_tx, &timer_tx));
                    },
                );
            } else {
                handle_netif_packets(
                    &netif,
                    |packet| {
                        Ipv4Packet::new(packet).map(|p| handle_main_inbound_packet(p, &state_tx));
                    },
                    |packet| {
                        Ipv6Packet::new(packet).map(|p| handle_main_inbound_packet(p, &state_tx));
                    },
                    |packet| {
                        Ipv4Packet::new(packet)
                            .map(|p| handle_main_outbound_packet(p, &state_tx, &timer_tx));
                    },
                    |packet| {
                        Ipv6Packet::new(packet)
                            .map(|p| handle_main_outbound_packet(p, &state_tx, &timer_tx));
                    },
                )
            }
        })
    };
    let side_netif_thread = {
        let netif = side_netif.clone();
        let state_tx = state_tx.clone();
        thread::spawn(move || {
            handle_netif_packets(
                &netif,
                |packet| {
                    Ipv4Packet::new(packet).map(|p| handle_side_inbound_packets(p, &state_tx));
                },
                |packet| {
                    Ipv6Packet::new(packet).map(|p| handle_side_inbound_packets(p, &state_tx));
                },
                |_| {},
                |_| {},
            )
        })
    };
    let state_handler_thread = thread::spawn(move || state_handler(state_rx));
    let timer_handler_thread = thread::spawn(move || timer_handler(&state_tx, timer_rx));

    info!("Started autogfw");

    main_netif_thread.join().unwrap();
    side_netif_thread.join().unwrap();
    state_handler_thread.join().unwrap();
    timer_handler_thread.join().unwrap();
}
