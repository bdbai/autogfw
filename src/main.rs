mod host;
mod packet;
mod state;

use {
    env_logger::{self, Env},
    log::{debug, error, info},
    once_cell::sync::OnceCell,
    packet::PacketSender,
    parking_lot::{Mutex, RwLock},
    rawsock::{
        self,
        pcap::{self, Direction},
        traits::DynamicInterface,
        traits::Library,
    },
    state::State,
    std::{
        collections::HashMap,
        process::exit,
        process::Command,
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

type Host = host::Host;
type StateArgs = (Host, state::State);
type TimerArgs = (Host, Instant);

const MAIN_OUTBOUND_FILTER: &str = "ip or ip6";
const MAIN_INBOUND_FILTER: &str = "ip or ip6";
const SIDE_INBOUND_FILTER: &str = "ip or ip6";

static OPT: OnceCell<Cli> = OnceCell::new();
static STATES: OnceCell<RwLock<HashMap<Host, Mutex<state::State>>>> = OnceCell::new();
static SIDE_SENDER: OnceCell<Mutex<PacketSender>> = OnceCell::new();
pub static LIB: OnceCell<pcap::Library> = OnceCell::new();

fn handle_main_outbound_packets(
    main_netif: &str,
    side_netif: &str,
    state_tx: Sender<StateArgs>,
    timer_tx: Sender<TimerArgs>,
) {
    let lib = LIB.get().unwrap();
    let mut main_netif = lib
        .open_interface(main_netif)
        .expect("Cannot open main interface");
    let data_link = main_netif.data_link();
    main_netif
        .set_filter(MAIN_OUTBOUND_FILTER)
        .expect("Cannot set main outbound filter");
    main_netif
        .set_direction(Direction::Out)
        .expect("Cannot set main outbound direction");
    SIDE_SENDER
        .set(Mutex::new(
            PacketSender::open(side_netif).expect("Cannot open side interface sender"),
        ))
        .map_err(|_| ())
        .unwrap();
    loop {
        let packet = if let Ok(packet) = main_netif.receive() {
            packet
        } else {
            // debug!("Skipped one packet in main outbound");
            continue;
        };
        let host = if let Some(host) = Host::dst_from_packet(&packet, data_link) {
            host
        } else {
            continue;
        };
        let states = STATES.get().unwrap().read();
        if states.get(&host).is_none() {
            state_tx.send((host, State::Pending)).unwrap();
            assert!(
                packet.len() >= 14,
                "Packet length should be greater than 14 bytes"
            );
            let test_packet = packet.into_owned();
            match SIDE_SENDER.get().unwrap().lock().send(&test_packet) {
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
}

fn handle_main_inbound_packets(netif: &str, state_tx: Sender<StateArgs>) {
    let mut netif = LIB
        .get()
        .unwrap()
        .open_interface(netif)
        .expect("Cannot open main interface");
    let data_link = netif.data_link();
    netif
        .set_filter(MAIN_INBOUND_FILTER)
        .expect("Cannot set main inbound filter");
    netif
        .set_direction(Direction::In)
        .expect("Cannot set main inbound direction");
    loop {
        let packet = if let Ok(packet) = netif.receive() {
            packet
        } else {
            // debug!("Skipped one packet in main inbound");
            continue;
        };
        let host = if let Some(host) = Host::src_from_packet(&packet, data_link) {
            host
        } else {
            continue;
        };
        let states = STATES.get().unwrap().read();
        if states
            .get(&host)
            .map_or(true, |state| *state.lock() != State::KnownDirect)
        {
            state_tx.send((host, State::KnownDirect)).unwrap();
        }
    }
}

fn handle_side_inbound_packets(netif: &str, state_tx: Sender<StateArgs>) {
    let mut netif = LIB
        .get()
        .unwrap()
        .open_interface(netif)
        .expect("Cannot open interface");
    let data_link = netif.data_link();
    netif
        .set_filter(SIDE_INBOUND_FILTER)
        .expect("Cannot set side filter");
    netif
        .set_direction(Direction::In)
        .expect("Cannot set side interface inbound direction");
    loop {
        let packet = if let Ok(packet) = netif.receive() {
            packet
        } else {
            // debug!("Skipped one packet in main outbound");
            continue;
        };
        let host = if let Some(host) = Host::src_from_packet(&packet, data_link) {
            host
        } else {
            continue;
        };
        let states = STATES.get().unwrap().read();
        if let Some(state) = states.get(&host) {
            if State::Pending == *state.lock() {
                state_tx.send((host, State::KnownProxy)).unwrap();
            }
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

fn timer_handler(state_tx: Sender<StateArgs>, timer_rx: Receiver<TimerArgs>) {
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
    let skip_main_inbound = opts.skip_main_inbound;
    let main_netif = opts.main_netif.to_string();
    let side_netif = opts.side_netif.to_string();
    if main_netif == side_netif {
        error!("Main interface cannot be the same as the side interface");
        exit(1);
    }
    let main_netif2 = main_netif.clone();
    let side_netif2 = side_netif.clone();
    OPT.set(opts).map_err(|_| ()).unwrap();
    STATES
        .set(RwLock::new(HashMap::with_capacity(1024)))
        .unwrap();

    LIB.set(pcap::Library::open_default_paths().expect("Cannot open pcap lib"))
        .map_err(|_| ())
        .unwrap();
    info!("Open pcap lib successfully");
    let (state_tx, state_rx) = channel();
    let (timer_tx, timer_rx) = channel();
    let state_tx1 = state_tx.clone();
    let state_tx2 = state_tx.clone();
    let state_tx3 = state_tx.clone();
    let timer_tx1 = timer_tx.clone();
    let main_netif_outbound_thread = thread::spawn(move || {
        handle_main_outbound_packets(
            main_netif.as_str(),
            side_netif.as_str(),
            state_tx1,
            timer_tx1,
        )
    });
    let main_netif_inbound_thread = if skip_main_inbound {
        None
    } else {
        Some(thread::spawn(move || {
            handle_main_inbound_packets(main_netif2.as_str(), state_tx2)
        }))
    };
    let side_netif_thread =
        thread::spawn(move || handle_side_inbound_packets(side_netif2.as_str(), state_tx));
    let state_handler_thread = thread::spawn(move || state_handler(state_rx));
    let timer_handler_thread = thread::spawn(move || timer_handler(state_tx3, timer_rx));
    info!("Started autogfw");
    main_netif_outbound_thread.join().unwrap();
    main_netif_inbound_thread.map(|t| t.join().unwrap());
    side_netif_thread.join().unwrap();
    state_handler_thread.join().unwrap();
    timer_handler_thread.join().unwrap();
}
