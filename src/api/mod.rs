//! Axum HTTP layer. Handlers here stay thin: parse the request, call
//! into a domain module (net/firewall/dhcp/dns), serialize the response.
//! No business logic belongs in this module.

pub mod auth;
pub mod dhcp;
pub mod dns;
pub mod firewall;
pub mod interfaces;
pub mod routes;
pub mod ws;

use crate::net::NetManager;
use std::sync::Arc;

/// Shared state injected into every handler via Axum's `State` extractor.
/// Add more managers here as they're built (DhcpManager, DnsManager, ...).
#[derive(Clone)]
pub struct AppState {
    pub net: Arc<NetManager>,
}
