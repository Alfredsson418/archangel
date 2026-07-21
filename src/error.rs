//! Shared error type for the whole application.
//!
//! Domain modules (net, firewall, dhcp, dns...) return `AppError` so the
//! API layer can convert any failure into a consistent HTTP response
//! without every module inventing its own error type.

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use serde_json::json;

#[derive(Debug, thiserror::Error)]
pub enum AppError {
    #[error("netlink error: {0}")]
    Netlink(String),

    #[error("firewall error: {0}")]
    Firewall(String),

    #[error("subprocess error: {0}")]
    Process(String),

    #[error("config error: {0}")]
    Config(String),

    #[error("not found: {0}")]
    NotFound(String),

    #[error("invalid request: {0}")]
    BadRequest(String),
}

// Lets domain modules `?`-propagate rtnetlink errors straight into AppError.
impl From<rtnetlink::Error> for AppError {
    fn from(e: rtnetlink::Error) -> Self {
        AppError::Netlink(e.to_string())
    }
}

// This is what turns an AppError into an actual HTTP response when it
// bubbles up out of an Axum handler.
impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let status = match &self {
            AppError::NotFound(_) => StatusCode::NOT_FOUND,
            AppError::BadRequest(_) => StatusCode::BAD_REQUEST,
            _ => StatusCode::INTERNAL_SERVER_ERROR,
        };

        let body = Json(json!({ "error": self.to_string() }));
        (status, body).into_response()
    }
}

pub type AppResult<T> = Result<T, AppError>;
