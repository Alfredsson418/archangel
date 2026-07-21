//! Persisted application config: desired state for firewall rules,
//! interfaces, DHCP scopes, DNS settings, etc. This is deliberately
//! separate from "live/applied state" - see `config::apply`.

pub mod apply;
pub mod schema;
pub mod store;
