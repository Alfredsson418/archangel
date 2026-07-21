use crate::error::AppResult;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct User {
    pub username: String,
    pub password_hash: String,
    pub is_admin: bool,
}

pub async fn authenticate(_username: &str, _password: &str) -> AppResult<Option<User>> {
    // Use `argon2` crate for password hashing when you get here.
    todo!("verify credentials against stored user record")
}
