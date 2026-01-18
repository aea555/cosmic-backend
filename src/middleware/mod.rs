//! Middleware modules for request processing.
//!
//! This module provides middleware for authentication and rate limiting.

pub mod rate_limit;

use crate::core::auth;
use crate::state::AppState;
#[allow(unused_imports)] // Used via generic insert() for request extensions
use crate::types::UserId;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::Response,
};

// Re-export rate limiting functions
pub use rate_limit::{auth_medium_rate_limit, auth_strict_rate_limit, user_rate_limit};

/// JWT authentication middleware.
///
/// Params: AppState, request, next middleware.
/// Logic: Extracts Bearer token, validates JWT, injects UserId into extensions.
/// Returns: Response from next handler or 401 Unauthorized.
pub async fn jwt_auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let token = extract_bearer_token(&request)?;

    let user_id = auth::validate_access_token(&token, &state.config).map_err(|_| {
        (
            StatusCode::UNAUTHORIZED,
            "Invalid or expired token".to_string(),
        )
    })?;

    // Inject user_id into request extensions for handlers to use
    request.extensions_mut().insert(user_id);

    Ok(next.run(request).await)
}

/// Extracts the Bearer token from the Authorization header.
///
/// Params: Request reference.
/// Logic: Parses "Bearer <token>" format.
/// Returns: Token string or error.
fn extract_bearer_token(request: &Request<Body>) -> Result<String, (StatusCode, String)> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or((
            StatusCode::UNAUTHORIZED,
            "Missing Authorization header".to_string(),
        ))?;

    if !auth_header.starts_with("Bearer ") {
        return Err((
            StatusCode::UNAUTHORIZED,
            "Invalid Authorization header format".to_string(),
        ));
    }

    Ok(auth_header[7..].to_string())
}
