//! Start/stop/restart the dnsmasq subprocess for DHCP.
//! Thin wrapper around `process::supervisor` with dnsmasq-specific args.

use crate::error::AppResult;
use crate::process::supervisor::Supervisor;

pub async fn start(_config_path: &str) -> AppResult<Supervisor> {
    // Supervisor::spawn("dnsmasq", &["-C", config_path, "--no-daemon"])
    todo!("spawn dnsmasq via the generic process supervisor")
}
