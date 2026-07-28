//! GET/POST handlers for /api/interfaces - this is the first real
//! end-to-end slice: HTTP -> netlink -> kernel -> JSON response.

use crate::api::AppState;
use crate::error::AppResult;
use crate::net::interfaces;
use axum::Json;
use axum::extract::{Path, State};
use serde::Deserialize;

pub async fn list(State(state): State<AppState>) -> AppResult<Json<Vec<interfaces::Interface>>> {
    let ifaces = interfaces::list(&state.net).await?;
    Ok(Json(ifaces))
}

#[derive(Deserialize)]
pub struct SetUpBody {
    pub up: bool,
}

pub async fn set_up(
    State(state): State<AppState>,
    Path(if_name): Path<String>,
    Json(body): Json<SetUpBody>,
) -> AppResult<Json<serde_json::Value>> {
    interfaces::set_link_state(&state.net, &if_name, body.up).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}
