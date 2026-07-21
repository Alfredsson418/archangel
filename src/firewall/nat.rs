//! NAT (masquerade) and port-forward rule management.

use crate::error::AppResult;

/// Enable outbound NAT (masquerade) from `lan_if` out through `wan_if`.
/// Roughly: `nft add rule inet nat postrouting oifname "wan0" masquerade`
pub async fn enable_masquerade(_wan_if: &str) -> AppResult<()> {
    todo!("add masquerade rule for the WAN interface")
}

pub struct PortForward {
    pub wan_port: u16,
    pub lan_address: String,
    pub lan_port: u16,
    pub protocol: String, // "tcp" | "udp"
}

pub async fn add_port_forward(_pf: PortForward) -> AppResult<()> {
    todo!("add DNAT rule for the port forward")
}
