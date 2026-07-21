//! Routing table management (default route, static routes).
//!
//! Stub for now - use `net.handle().route()` (v4()/v6() variants).

use crate::error::AppResult;
use crate::net::NetManager;
use serde::Serialize;

#[derive(Debug, Serialize)]
pub struct Route {
    pub destination: String,
    pub gateway: Option<String>,
    pub interface_index: u32,
}

pub async fn list(_net: &NetManager) -> AppResult<Vec<Route>> {
    todo!("list routes via net.handle().route().get()")
}
