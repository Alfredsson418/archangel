//! CPU/memory/disk/uptime of the box itself, for the dashboard.

use serde::Serialize;
use sysinfo::System;
use tokio::sync::Mutex;

#[derive(Debug, Serialize)]
pub struct CoreStats {
    pub usage: f32, 
    pub name: String,
    pub vendor_id: String,
    pub brand: String,
    pub frequency: u64,
}

#[derive(Debug, Serialize)]
pub struct CPUStats {
    pub percent: f32,
    pub nr_cores: usize,
    pub cores: Vec<CoreStats>,
}

#[derive(Debug, Serialize)]
pub struct MemoryStats {
    pub used_bytes: u64,
    pub total_bytes: u64,
}

#[derive(Debug, Serialize)]
pub struct SystemStats {
    pub cpu: CPUStats,
    pub memory: MemoryStats,
    pub uptime_secs: u64,
}

/// Holds the one sysinfo::System instance for the app's lifetime.
/// Wrapped in a Mutex because multiple request handlers might call
/// `current()` concurrently, and refreshing mutates internal state.
pub struct SystemMonitor {
    sys: Mutex<System>,
}

impl SystemMonitor {
    pub fn new() -> Self {
        let mut sys = System::new_all();
        sys.refresh_all();
        Self {
            sys: Mutex::new(sys),
        }
    }

    pub async fn cpu_percent(&self) -> f32 {
        let mut sys = self.sys.lock().await;
        sys.refresh_cpu_usage();
        sys.global_cpu_usage()
    }

    pub async fn nr_cores(&self) -> usize {
        let mut sys = self.sys.lock().await;
        sys.refresh_cpu_usage();
        sys.cpus().len()
    }

    pub async fn all_core_info(&self) -> Vec<CoreStats> {
        let mut sys = self.sys.lock().await;
        sys.refresh_cpu_all();
        let mut cores: Vec<CoreStats> = Vec::new();
        for cpu in sys.cpus() {
            cores.push(CoreStats {
                usage: cpu.cpu_usage(),
                name: cpu.name().to_string(),
                vendor_id: cpu.vendor_id().to_string(),
                frequency: cpu.frequency(),
                brand: cpu.brand().to_string(),
            });
        } 
        cores
    }

    pub async fn memory(&self) -> (u64, u64) {
        let mut sys = self.sys.lock().await;
        sys.refresh_memory();
        (sys.used_memory(), sys.total_memory())
    }

    pub fn uptime_secs(&self) -> u64 {
        System::uptime()
    }

    pub async fn current(&self) -> SystemStats {
        SystemStats {
            cpu: CPUStats {
                percent: self.cpu_percent().await,
                nr_cores: self.nr_cores().await,
                cores: self.all_core_info().await,
            }, 
            memory: MemoryStats {
                used_bytes: self.memory().await.0,
                total_bytes: self.memory().await.1,
            },
            uptime_secs: self.uptime_secs(),
        }
    }
}
