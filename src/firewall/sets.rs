//! nftables named sets - useful for blocklists/allowlists that update
//! frequently without rewriting the whole ruleset (e.g. a dynamic IP
//! blocklist fed by an IDS later on).

use crate::error::AppResult;

pub async fn create_set(_name: &str, _set_type: &str) -> AppResult<()> {
    // e.g. nft add set inet filter <name> {{ type <set_type>; }}
    todo!("create an nftables named set")
}

pub async fn add_element(_set_name: &str, _element: &str) -> AppResult<()> {
    // e.g. nft add element inet filter <set_name> {{ <element> }}
    todo!("add an element to an nftables named set")
}
