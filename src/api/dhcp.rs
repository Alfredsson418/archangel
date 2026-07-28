//! Handlers for /api/dhcp/* - leases + scope config.

use crate::dhcp::leases::{self, Lease};
use crate::error::AppResult;
use axum::Json;

pub async fn list_leases() -> AppResult<Json<Vec<Lease>>> {
    // TODO: pull the real lease file path from app config
    Ok(Json(leases::list("/var/lib/misc/dnsmasq.leases").await?))
}
