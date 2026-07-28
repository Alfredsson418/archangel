use crate::stats::system::SystemStats;
use crate::{api::AppState, error::AppResult};
use axum::Json;
use axum::extract::State;


// It could be useful to split up some systeminfo to General, CPU, Memory, Disk, etc because it may
// be too much info for one call.
pub async fn get_system_stats(State(state): State<AppState>) -> AppResult<Json<SystemStats>> {
    let stats = state.sysmon.current().await;
    Ok(Json(stats))
}
