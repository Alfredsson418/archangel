//! WireGuard interface + peer management.
//! Likely via `wg`/`wg-quick` subprocess calls or the `netlink-wg` crate.

use crate::error::AppResult;

pub async fn create_interface(_name: &str, _listen_port: u16) -> AppResult<()> {
    todo!("create a wireguard interface")
}

pub async fn add_peer(_interface: &str, _public_key: &str, _allowed_ips: &str) -> AppResult<()> {
    todo!("add a wireguard peer")
}
