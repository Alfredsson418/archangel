//! Handlers for /api/firewall/* - delegate to the `firewall` domain module.

use crate::error::AppResult;
use crate::firewall::{FirewallRule, rules};
use axum::Json;
use axum::extract::Path;

pub async fn list() -> AppResult<Json<Vec<FirewallRule>>> {
    Ok(Json(rules::list().await?))
}

pub async fn create(Json(rule): Json<FirewallRule>) -> AppResult<Json<serde_json::Value>> {
    rules::create(rule).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}

pub async fn delete(Path(id): Path<String>) -> AppResult<Json<serde_json::Value>> {
    rules::delete(&id).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}
