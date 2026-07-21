//! Handlers for /api/auth/* - login/logout.

use crate::auth::{session, users};
use crate::error::{AppError, AppResult};
use axum::Json;
use serde::Deserialize;

#[derive(Deserialize)]
pub struct LoginBody {
    pub username: String,
    pub password: String,
}

pub async fn login(Json(body): Json<LoginBody>) -> AppResult<Json<serde_json::Value>> {
    let user = users::authenticate(&body.username, &body.password)
        .await?
        .ok_or_else(|| AppError::BadRequest("invalid credentials".into()))?;

    let token = session::create_session(&user.username).await?;
    Ok(Json(serde_json::json!({ "token": token })))
}
