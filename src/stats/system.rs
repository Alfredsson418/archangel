//! CPU/memory/disk/uptime of the box itself, for the dashboard.

use crate::error::AppResult;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub cpu_percent: f32,
    pub mem_used_bytes: u64,
    pub mem_total_bytes: u64,
    pub uptime_secs: u64,
}

pub async fn current() -> AppResult<SystemStats> {
    // Consider the `sysinfo` crate here instead of parsing /proc by hand.
    todo!("gather system stats")
}
