mod api;
mod auth;
mod config;
mod dhcp;
mod dns;
mod error;
mod firewall;
mod net;
mod process;
mod stats;
mod vpn;
mod cli;
mod params;
mod output;

use api::AppState;
use net::NetManager;
use std::sync::Arc;
use clap::Parser;

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    println!("{}", output::motd::motd());

    let args = cli::App::parse();

    tracing_subscriber::fmt::init();

    // Opens the netlink connection - see net/mod.rs. This is the only
    // thing needed to get the `/api/interfaces` endpoint working.
    let net = Arc::new(NetManager::new()?);
    let state = AppState { net };

    let app = api::routes::build_router(state);

    let listener = tokio::net::TcpListener::bind("127.0.0.1:8080").await?;
    tracing::info!("archangel listening on http://127.0.0.1:8080");

    axum::serve(listener, app).await?;
    Ok(())
}
