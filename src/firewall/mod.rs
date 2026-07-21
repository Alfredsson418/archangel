//! nftables-backed firewall rule management.
//!
//! Early on, shelling out to `nft -j` (JSON I/O) is simpler and more
//! transparent than the `nftables` crate's netlink API - you can literally
//! print what you're about to apply. Swap to a lower-level crate later
//! if you need it, once the rule model is stable.

pub mod apply;
pub mod nat;
pub mod rules;
pub mod sets;

use serde::{Deserialize, Serialize};

/// A single firewall rule in your app's own model - this is what the API
/// and frontend deal with. `rules::to_nft_json` translates this into the
/// actual nftables ruleset.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FirewallRule {
    pub id: String,
    pub description: String,
    pub interface: Option<String>,
    pub source: Option<String>,
    pub destination: Option<String>,
    pub protocol: Option<String>, // "tcp" | "udp" | "icmp" | ...
    pub dest_port: Option<u16>,
    pub action: RuleAction,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RuleAction {
    Accept,
    Drop,
    Reject,
}
