mod api;
mod auth;
mod cli;
mod config;
mod dhcp;
mod dns;
mod error;
mod firewall;
mod net;
mod output;
mod params;
mod process;
mod stats;
mod vpn;

use api::AppState;
use clap::Parser;
use net::NetManager;
use stats::system::SystemMonitor;
use std::sync::Arc;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", output::motd::motd());

    let args = cli::App::parse();

    tracing_subscriber::fmt::init();

    // Opens the netlink connection - see net/mod.rs. This is the only
    // thing needed to get the `/api/interfaces` endpoint working.
    let net = Arc::new(NetManager::new()?);
    let sysmon = Arc::new(SystemMonitor::new());
    let state = AppState { net, sysmon };

    let app = api::routes::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    tracing::info!("archangel listening on http://127.0.0.1:8080");

    axum::serve(listener, app).await?;
    Ok(())
}
