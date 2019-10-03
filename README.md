# Autogfw

Swith route automatically by realtime active detection.

*Linux only*

## Usage
1. Ensure `libpcap` or `libpcap-dev` installed on your system.
2. Run with the following command
```sh
# Turn on debug logging
export RUST_LOG=debug
# Add privileges for raw packet processing
sudo setcap cap_net_raw,cap_net_admin=eip ./autogfw
# Start autogfw
./autogfw -m enp4s0 -s enp4s1 -c via 10.10.1.1 dev enp4s1
```
where:
- `enp4s0` is the main network interface (ether datalink)
- `enp4s1` is the backup network interface (through VPN)
- `10.10.1.1` is the gateway address to use for the backup network interface

See `./autogfw --help` for more information.

## Build
1. Ensure `rustup` is installed on your system. See https://rustup.rs
2. Install nightly (2019-09-21) toolchain with `rustup install nightly-2019-09-21`
3. `cargo build --release`
