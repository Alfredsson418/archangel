//! Generic "spawn, monitor, restart on failure" supervisor for managed
//! subprocesses (dnsmasq, unbound, wireguard-tools, etc.), so dhcp/dns/vpn
//! don't each reimplement process lifecycle handling.

use crate::error::{AppError, AppResult};
use tokio::process::{Child, Command};

pub struct Supervisor {
    child: Child,
    #[allow(dead_code)]
    name: String,
}

impl Supervisor {
    /// Spawn a subprocess and return a handle to it. Caller is
    /// responsible for calling `.wait_and_restart()` in a background
    /// task if auto-restart-on-crash is desired.
    pub async fn spawn(bin: &str, args: &[&str]) -> AppResult<Self> {
        let child = Command::new(bin)
            .args(args)
            .kill_on_drop(true)
            .spawn()
            .map_err(|e| AppError::Process(format!("failed to spawn {bin}: {e}")))?;

        Ok(Self {
            child,
            name: bin.to_string(),
        })
    }

    pub async fn stop(mut self) -> AppResult<()> {
        self.child
            .kill()
            .await
            .map_err(|e| AppError::Process(e.to_string()))
    }

    // TODO: add a `supervise()` loop that awaits the child, and on
    // unexpected exit, respawns with backoff - spawn this as a
    // tokio::task from wherever DHCP/DNS/VPN services are started.
}
