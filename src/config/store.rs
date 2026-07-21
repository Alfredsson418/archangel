//! Load/save AppConfig to disk. Starting with a JSON/TOML file is fine;
//! move to SQLite once you need concurrent writes, history, or multi-user
//! audit trails.

use crate::config::schema::AppConfig;
use crate::error::{AppError, AppResult};

const DEFAULT_CONFIG_PATH: &str = "/etc/netfence/config.json";

pub async fn load(path: Option<&str>) -> AppResult<AppConfig> {
    let path = path.unwrap_or(DEFAULT_CONFIG_PATH);
    let bytes = tokio::fs::read(path)
        .await
        .map_err(|e| AppError::Config(format!("failed to read {path}: {e}")))?;

    serde_json::from_slice(&bytes)
        .map_err(|e| AppError::Config(format!("failed to parse {path}: {e}")))
}

pub async fn save(config: &AppConfig, path: Option<&str>) -> AppResult<()> {
    let path = path.unwrap_or(DEFAULT_CONFIG_PATH);
    let bytes = serde_json::to_vec_pretty(config)
        .map_err(|e| AppError::Config(format!("failed to serialize config: {e}")))?;

    tokio::fs::write(path, bytes)
        .await
        .map_err(|e| AppError::Config(format!("failed to write {path}: {e}")))
}
