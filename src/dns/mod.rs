//! DNS resolver management - wraps `unbound` as a managed subprocess.

pub mod config_gen;
pub mod process;
pub mod records;

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DnsSettings {
    pub upstream_servers: Vec<String>, // e.g. ["1.1.1.1", "9.9.9.9"]
    pub listen_interfaces: Vec<String>,
    pub dnssec_enabled: bool,
}
