//! Live monitoring: traffic counters, system health. Feeds the
//! dashboard via the WebSocket endpoint in `api::ws`.

pub mod system;
pub mod traffic;

use sysinfo::System;
use tokio::sync::Mutex;

/// Holds the one sysinfo::System instance for the app's lifetime.
/// Wrapped in a Mutex because multiple request handlers might call
/// `current()` concurrently, and refreshing mutates internal state.
pub struct SystemMonitor {
    sys: Mutex<System>,
}

impl SystemMonitor {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all(); // prime it with a first reading
        Self { sys: Mutex::new(sys) }
    }

    pub async fn current(&self) -> SystemStats {
        // .lock().await waits its turn if something else is using `sys`
        let mut sys = self.sys.lock().await;
        sys.refresh_cpu_usage();
        sys.refresh_memory();

        SystemStats {
            cpu_percent: sys.global_cpu_usage(),
            mem_used_bytes: sys.used_memory(),
            mem_total_bytes: sys.total_memory(),
        }
    }
}
