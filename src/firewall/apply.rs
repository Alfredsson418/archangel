//! Apply the desired ruleset to the kernel, with a rollback safety net.
//!
//! This is the pfSense/OPNsense "apply changes" pattern: push the new
//! ruleset, start a timer, and if the user (or your own health check)
//! doesn't confirm within N seconds, automatically revert to the last
//! known-good ruleset. Prevents locking yourself out over SSH/web UI
//! after a bad rule change.

use crate::error::AppResult;
use std::time::Duration;

pub const ROLLBACK_TIMEOUT: Duration = Duration::from_secs(30);

/// Serialize all current rules/NAT/sets into a full nft ruleset and load
/// it atomically (`nft -f <file>` replaces the whole ruleset in one go,
/// which avoids half-applied states).
pub async fn apply_all() -> AppResult<()> {
    // 1. Snapshot current live ruleset (for rollback) - `nft list ruleset`
    // 2. Build the new ruleset text from firewall::rules + nat + sets
    // 3. Write to a temp file, `nft -c -f <file>` to check syntax first
    // 4. `nft -f <file>` to apply
    // 5. Start a rollback timer; caller must call `confirm()` before it
    //    fires or the snapshot from step 1 gets re-applied.
    todo!("apply the full ruleset with rollback safety")
}

/// Call this from the frontend once the admin confirms the new ruleset
/// didn't lock them out.
pub async fn confirm() -> AppResult<()> {
    todo!("cancel the pending rollback timer")
}
