//! VLAN sub-interface creation (e.g. eth0.10 tagged VLAN 10).
//!
//! Stub for now - use net.handle().link().add().vlan(name, parent_index, vlan_id).

use crate::error::AppResult;
use crate::net::NetManager;

pub async fn create_vlan(
    _net: &NetManager,
    _parent_if_index: u32,
    _vlan_id: u16,
    _name: &str,
) -> AppResult<()> {
    todo!("create a VLAN sub-interface")
}
