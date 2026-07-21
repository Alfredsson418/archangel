//! Per-interface traffic counters, pulled from nftables rule counters
//! or /proc/net/dev as a simpler starting point.

use crate::error::AppResult;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct InterfaceTraffic {
    pub interface: String,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

pub async fn current() -> AppResult<Vec<InterfaceTraffic>> {
    // Simplest starting point: parse /proc/net/dev
    todo!("read interface byte counters")
}
