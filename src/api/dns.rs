//! Handlers for /api/dns/* - local records + resolver settings.

use crate::dns::records::{self, DnsRecord};
use crate::error::AppResult;
use axum::Json;

pub async fn list_records() -> AppResult<Json<Vec<DnsRecord>>> {
    Ok(Json(records::list().await?))
}

pub async fn create_record(Json(record): Json<DnsRecord>) -> AppResult<Json<serde_json::Value>> {
    records::create(record).await?;
    Ok(Json(serde_json::json!({ "status": "ok" })))
}
