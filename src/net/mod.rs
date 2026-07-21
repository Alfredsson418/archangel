//! Netlink-backed network state: interfaces, addresses, routes, VLANs.
//!
//! Everything here talks to the kernel via `rtnetlink` and knows nothing
//! about HTTP. The `api::interfaces` handlers call into this module.

pub mod addresses;
pub mod interfaces;
pub mod routes;
pub mod vlan;

use rtnetlink::Handle;

/// Thin wrapper around the rtnetlink handle, shared across the app
/// (put this in Axum's `State` once you wire up the server).
#[derive(Clone)]
pub struct NetManager {
    handle: Handle,
}

impl NetManager {
    /// Opens a netlink connection and spawns the background task that
    /// drives it. Call this once at startup.
    pub fn new() -> std::io::Result<Self> {
        let (connection, handle, _) = rtnetlink::new_connection()?;
        tokio::spawn(connection);
        Ok(Self { handle })
    }

    pub fn handle(&self) -> &Handle {
        &self.handle
    }
}
