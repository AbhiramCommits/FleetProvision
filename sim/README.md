# sim/

The network and boot simulators are implemented in Rust as the `fleet-sim`
crate (`crates/fleet-sim`) rather than Python. They bind real UDP/TCP sockets:

* DHCP (offer/ack/nak) and TFTP (RRQ/DATA/ACK/ERROR)
* DNS A records for `*.fleet.internal`
* HTTP provisioning (iPXE, Kickstart, cloud-init, bootstrap tokens)
* The simulated 802.1X authenticator with an EAP-TLS-shaped JSON handshake
* The full `fleet-sim e2e` orchestrator and benchmark harness

There is intentionally no Python virtualenv here. See `crates/fleet-sim/src/`
for `net.rs`, `dot1x.rs`, `render.rs`, and `e2e.rs`.
