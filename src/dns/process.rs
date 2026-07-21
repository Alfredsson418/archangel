//! Start/stop/restart the unbound subprocess for DNS resolution.

use crate::error::AppResult;
use crate::process::supervisor::Supervisor;

pub async fn start(_config_path: &str) -> AppResult<Supervisor> {
    // Supervisor::spawn("unbound", &["-c", config_path, "-d"])
    todo!("spawn unbound via the generic process supervisor")
}
