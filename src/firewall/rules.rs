//! CRUD for firewall rules + translation into nftables syntax.

use crate::error::AppResult;
use crate::firewall::FirewallRule;

/// In-memory/placeholder store for now - replace with the config store
/// (see `config::store`) once persistence is wired up.
pub async fn list() -> AppResult<Vec<FirewallRule>> {
    todo!("return rules from the config store")
}

pub async fn create(_rule: FirewallRule) -> AppResult<()> {
    todo!("validate + persist rule, then call firewall::apply::apply_all()")
}

pub async fn delete(_id: &str) -> AppResult<()> {
    todo!("remove rule from store, then re-apply")
}

/// Translate our rule model into an `nft` command (or JSON payload for
/// `nft -j -f -`). Starting with plain command strings is fine early on:
///
/// e.g. FirewallRule { source: Some("10.0.0.0/24"), action: Drop, .. }
///   -> "add rule inet filter forward ip saddr 10.0.0.0/24 drop"
pub fn to_nft_command(_rule: &FirewallRule) -> String {
    todo!("translate FirewallRule into an nft rule command")
}
