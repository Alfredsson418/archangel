//! Builds the full Axum router. `main.rs` just calls `build_router()`
//! and serves it.

use crate::api::stats::get_system_stats;
use crate::api::{AppState, auth, dhcp, dns, firewall, interfaces, ws, stats};
use axum::Router;
use axum::routing::{delete, get, post};

pub fn build_router(state: AppState) -> Router {
    Router::new()
        .route("/api/interfaces", get(interfaces::list))
        // .route("/api/interfaces/{name}/state", post(interfaces::set_up)) // These parameterized
        // urls need to be handel in a different way when calling the function, see https://github.com/tokio-rs/axum/blob/main/examples/templates/src/main.rs
        // .route("/api/firewall/rules", get(firewall::list).post(firewall::create))
        // .route("/api/firewall/rules/{id}", delete(firewall::delete))
        // .route("/api/dhcp/leases", get(dhcp::list_leases))
        // .route("/api/dns/records", get(dns::list_records).post(dns::create_record))
        // .route("/api/auth/login", post(auth::login))
        // .route("/api/ws", get(ws::upgrade))
        .route("/api/system", get(stats::get_system_stats))
        .with_state(state)
}
