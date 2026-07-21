//! DHCP server management - wraps `dnsmasq` (simplest to start with) as a
//! managed subprocess rather than implementing DHCP from scratch.

pub mod config_gen;
pub mod leases;
pub mod process;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DhcpScope {
    pub interface: String,
    pub range_start: String,
    pub range_end: String,
    pub subnet_mask: String,
    pub lease_time_secs: u32,
    pub gateway: Option<String>,
    pub dns_servers: Vec<String>,
}
