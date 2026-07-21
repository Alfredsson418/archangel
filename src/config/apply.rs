//! Orchestrates applying the full desired config to the live system:
//! firewall rules, DHCP config regen + restart, DNS config regen + restart.
//!
//! This is the single entry point the "Apply Changes" button in the UI
//! should call - it should NOT be possible to apply firewall changes
//! without going through here, or the rollback safety net (see
//! `firewall::apply`) gets bypassed.

use crate::config::schema::AppConfig;
use crate::error::AppResult;

pub async fn apply_config(_config: &AppConfig) -> AppResult<()> {
    // 1. crate::firewall::apply::apply_all() (with rollback timer)
    // 2. crate::dhcp::config_gen::write_config(...) + restart dnsmasq
    // 3. crate::dns::config_gen::write_config(...) + restart unbound
    // 4. crate::config::store::save(config, None) once confirmed
    todo!("apply full desired config to the live system")
}
