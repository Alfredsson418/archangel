//! IP address management for interfaces (get/add/remove addresses).
//!
//! Stub for now - mirrors the pattern in `interfaces.rs`:
//! `net.handle().address().get()/.add()/.del()`.

use crate::error::AppResult;
use crate::net::NetManager;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct IpAddress {
    pub interface_index: u32,
    pub address: String,
    pub prefix_len: u8,
}

pub async fn list_for_interface(_net: &NetManager, _if_index: u32) -> AppResult<Vec<IpAddress>> {
    // TODO: use net.handle().address().get().set_link_index_filter(if_index)
    todo!("list addresses for an interface")
}

pub async fn add(
    _net: &NetManager,
    _if_index: u32,
    _address: &str,
    _prefix_len: u8,
) -> AppResult<()> {
    // TODO: use net.handle().address().add(if_index, addr, prefix_len).execute()
    todo!("add an IP address to an interface")
}
