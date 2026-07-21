use crate::error::AppResult;

pub async fn create_session(_username: &str) -> AppResult<String> {
    // Generate a signed token/cookie (e.g. via `jsonwebtoken` or a random
    // opaque token stored server-side).
    todo!("create a session token")
}

pub async fn validate_session(_token: &str) -> AppResult<Option<String>> {
    todo!("validate a session token, return the username if valid")
}
