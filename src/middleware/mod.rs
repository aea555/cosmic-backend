//! Middleware modules for request processing.
//!
//! This module provides middleware for authentication and rate limiting.

pub mod rate_limit;

use crate::core::auth;
use crate::state::AppState;
#[allow(unused_imports)] // Used via generic insert() for request extensions
use crate::types::UserId;
use axum::{
    Json,
    body::Body,
    extract::State,
    http::{Request, StatusCode, header::AUTHORIZATION},
    middleware::Next,
    response::{IntoResponse, Response},
};
use serde::Serialize;

// Re-export rate limiting functions
pub use rate_limit::{auth_medium_rate_limit, auth_strict_rate_limit, user_rate_limit};

/// Error response for authentication failures.
#[derive(Serialize)]
struct AuthErrorResponse {
    success: bool,
    error: String,
    code: String,
}

impl AuthErrorResponse {
    fn new(error: impl Into<String>, code: impl Into<String>) -> Self {
        Self {
            success: false,
            error: error.into(),
            code: code.into(),
        }
    }
}

/// Creates a 401 Unauthorized JSON response.
fn unauthorized_response(error: &str, code: &str) -> Response {
    (
        StatusCode::UNAUTHORIZED,
        Json(AuthErrorResponse::new(error, code)),
    )
        .into_response()
}

/// JWT authentication middleware.
///
/// Params: AppState, request, next middleware.
/// Logic: Extracts Bearer token, validates JWT, injects UserId into extensions.
/// Returns: Response from next handler or 401 Unauthorized.
pub async fn jwt_auth(
    State(state): State<AppState>,
    mut request: Request<Body>,
    next: Next,
) -> Response {
    let token = match extract_bearer_token(&request) {
        Ok(t) => t,
        Err(response) => return response,
    };

    let user_id = match auth::validate_access_token(&token, &state.config) {
        Ok(id) => id,
        Err(_) => {
            return unauthorized_response("Invalid or expired token", "INVALID_TOKEN");
        }
    };

    // Inject user_id into request extensions for handlers to use
    request.extensions_mut().insert(user_id);

    next.run(request).await
}

/// Extracts the Bearer token from the Authorization header.
///
/// Params: Request reference.
/// Logic: Parses "Bearer <token>" format.
/// Returns: Token string or error response.
fn extract_bearer_token(request: &Request<Body>) -> Result<String, Response> {
    let auth_header = request
        .headers()
        .get(AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or_else(|| {
            unauthorized_response("Missing Authorization header", "MISSING_AUTH_HEADER")
        })?;

    if !auth_header.starts_with("Bearer ") {
        return Err(unauthorized_response(
            "Invalid Authorization header format",
            "INVALID_AUTH_FORMAT",
        ));
    }

    Ok(auth_header[7..].to_string())
}
