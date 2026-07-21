//! Live monitoring: traffic counters, system health. Feeds the
//! dashboard via the WebSocket endpoint in `api::ws`.

pub mod system;
pub mod traffic;
