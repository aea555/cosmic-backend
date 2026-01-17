//! Authentication HTTP handlers.
//!
//! This module contains the HTTP handlers for authentication endpoints.
//! Handlers are thin and delegate to core business logic.

use crate::core::auth;
use crate::error::{AppError, AppJson, AppResult};
use crate::handlers::email;
use crate::state::AppState;
use crate::types::{
    ApiResponse, AuthResponse, AuthResponseWrapper, EmptyResponseWrapper, LoginRequest,
    RefreshRequest, RegisterRequest, ResendVerificationRequest, VerifyEmailRequest,
};
use axum::{Json, extract::State, http::StatusCode};
use validator::Validate;

/// Handles user registration.
///
/// Params: AppState, RegisterRequest body.
/// Logic: Validates input, creates user, sends verification email.
/// Returns: 201 Created with message on success.
///
/// POST /api/v1/auth/register
#[utoipa::path(
    post,
    path = "/api/v1/auth/register",
    request_body = RegisterRequest,
    responses(
        (status = 201, description = "Registration successful", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 409, description = "User already exists", body = EmptyResponseWrapper)
    ),
    tag = "auth"
)]
pub async fn register(
    State(state): State<AppState>,
    AppJson(request): AppJson<RegisterRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<()>>)> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let (user_id, verification_token) =
        auth::register_user(&state.db, &request.email, &request.password, &state.config).await?;

    // Send verification email
    if let Err(e) =
        email::send_verification_email(&state.config, &request.email, &verification_token).await
    {
        tracing::error!("Failed to send verification email: {}", e);
        // Continue anyway - user can request resend
    }

    tracing::info!("User registered: {}", user_id);

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: Some(
                "Registration successful. Please check your email to verify your account."
                    .to_string(),
            ),
            data: None,
        }),
    ))
}

/// Handles email verification.
///
/// Params: AppState, VerifyEmailRequest body.
/// Logic: Validates token, marks email as verified.
/// Returns: 200 OK with message on success.
///
/// POST /api/v1/auth/verify-email
#[utoipa::path(
    post,
    path = "/api/v1/auth/verify-email",
    request_body = VerifyEmailRequest,
    responses(
        (status = 200, description = "Email verified", body = EmptyResponseWrapper),
        (status = 403, description = "Invalid token", body = EmptyResponseWrapper)
    ),
    tag = "auth"
)]
pub async fn verify_email(
    State(state): State<AppState>,
    AppJson(request): AppJson<VerifyEmailRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    auth::verify_email(&state.db, &request.token).await?;

    tracing::info!("Email verified successfully");

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Email verified successfully. You can now log in.".to_string()),
        data: None,
    }))
}

/// Handles resending verification email.
///
/// Params: AppState, ResendVerificationRequest body.
/// Logic: Checks user exists, not verified, no active token, sends new email.
/// Returns: 200 OK with message on success.
///
/// POST /api/v1/auth/resend-verification
#[utoipa::path(
    post,
    path = "/api/v1/auth/resend-verification",
    request_body = ResendVerificationRequest,
    responses(
        (status = 200, description = "Verification email sent", body = EmptyResponseWrapper),
        (status = 404, description = "User not found", body = EmptyResponseWrapper),
        (status = 409, description = "Email already verified", body = EmptyResponseWrapper),
        (status = 429, description = "Verification pending or rate limited", body = EmptyResponseWrapper)
    ),
    tag = "auth"
)]
pub async fn resend_verification(
    State(state): State<AppState>,
    AppJson(request): AppJson<ResendVerificationRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    use crate::core::crypto;
    use crate::repository;
    use chrono::{Duration, Utc};

    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    // Find user by email
    let user = repository::user::find_by_email(&state.db, &request.email).await?;

    // Check if already verified
    if user.email_verified {
        return Err(AppError::EmailAlreadyVerified);
    }

    // Check for active (non-expired) verification token
    if let Some(active_token) =
        repository::verification::find_active_for_user(&state.db, user.id).await?
    {
        let retry_after = (active_token.expires_at - Utc::now()).num_seconds().max(0);
        return Err(AppError::VerificationPending {
            retry_after_seconds: retry_after,
        });
    }

    // Delete any expired tokens
    repository::verification::delete_all_for_user(&state.db, user.id).await?;

    // Generate new verification token
    let verification_token = crypto::generate_verification_token();
    let token_hash = crypto::hash_verification_token(&verification_token);
    let expires_at = Utc::now() + Duration::hours(24);

    repository::verification::create(&state.db, user.id, &token_hash, expires_at).await?;

    // Send verification email
    if let Err(e) =
        email::send_verification_email(&state.config, &request.email, &verification_token).await
    {
        tracing::error!("Failed to send verification email: {}", e);
        return Err(e);
    }

    tracing::info!("Verification email resent to user: {}", user.id);

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Verification email sent. Please check your inbox.".to_string()),
        data: None,
    }))
}

/// Handles user login.
///
/// Params: AppState, LoginRequest body.
/// Logic: Validates credentials, generates tokens (uses cache for canary lookup).
/// Returns: 200 OK with tokens on success.
///
/// POST /api/v1/auth/login
#[utoipa::path(
    post,
    path = "/api/v1/auth/login",
    request_body = LoginRequest,
    responses(
        (status = 200, description = "Login successful", body = AuthResponseWrapper),
        (status = 401, description = "Invalid credentials", body = EmptyResponseWrapper),
        (status = 429, description = "Rate limit exceeded", body = EmptyResponseWrapper)
    ),
    tag = "auth"
)]
pub async fn login(
    State(state): State<AppState>,
    AppJson(request): AppJson<LoginRequest>,
) -> AppResult<Json<ApiResponse<AuthResponse>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let auth_response = auth::login(
        &state.db,
        &state.cache,
        &request.email,
        &request.password,
        &state.config,
    )
    .await?;

    tracing::info!("User logged in: {}", request.email);

    Ok(Json(ApiResponse::success(auth_response)))
}

/// Handles token refresh.
///
/// Params: AppState, RefreshRequest body.
/// Logic: Validates and rotates refresh token (checks cache blacklist).
/// Returns: 200 OK with new tokens on success.
///
/// POST /api/v1/auth/refresh
#[utoipa::path(
    post,
    path = "/api/v1/auth/refresh",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Token refreshed", body = AuthResponseWrapper),
        (status = 401, description = "Invalid or expired refresh token", body = EmptyResponseWrapper)
    ),
    tag = "auth"
)]
pub async fn refresh(
    State(state): State<AppState>,
    AppJson(request): AppJson<RefreshRequest>,
) -> AppResult<Json<ApiResponse<AuthResponse>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let auth_response = auth::refresh_tokens(
        &state.db,
        &state.cache,
        &request.refresh_token,
        &state.config,
    )
    .await?;

    tracing::debug!("Token refreshed");

    Ok(Json(ApiResponse::success(auth_response)))
}

/// Handles user logout.
///
/// Params: AppState, RefreshRequest body.
/// Logic: Revokes the refresh token and adds to cache blacklist.
/// Returns: 200 OK with message on success.
///
/// POST /api/v1/auth/logout
#[utoipa::path(
    post,
    path = "/api/v1/auth/logout",
    request_body = RefreshRequest,
    responses(
        (status = 200, description = "Logged out successfully", body = EmptyResponseWrapper)
    ),
    tag = "auth"
)]
pub async fn logout(
    State(state): State<AppState>,
    AppJson(request): AppJson<RefreshRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    auth::logout(&state.db, &state.cache, &request.refresh_token).await?;

    tracing::debug!("User logged out");

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Logged out successfully".to_string()),
        data: None,
    }))
}

/// Redirects email verification to mobile app or web page based on User-Agent.
///
/// Params: AppState, token query param, request headers.
/// Logic:
///   1. Detects if request is from mobile (Android/iOS) via User-Agent.
///   2. Mobile: Redirects to deep link (e.g., cosmicvault://verify-email?token=X).
///   3. Desktop: Shows a simple HTML page with instructions.
///
/// GET /api/v1/auth/verify-redirect?token=X
#[utoipa::path(
    get,
    path = "/api/v1/auth/verify-redirect",
    params(
        ("token" = String, Query, description = "Email verification token")
    ),
    responses(
        (status = 302, description = "Redirects to mobile app deep link"),
        (status = 200, description = "Shows web verification page"),
        (status = 400, description = "Missing token")
    ),
    tag = "auth"
)]
pub async fn verify_redirect(
    State(state): State<AppState>,
    axum::extract::Query(params): axum::extract::Query<std::collections::HashMap<String, String>>,
    headers: axum::http::HeaderMap,
) -> axum::response::Response {
    use axum::response::{Html, IntoResponse, Redirect};

    // Extract token from query params
    let token = match params.get("token") {
        Some(t) if !t.is_empty() => t,
        _ => {
            return Html(
                r#"
<!DOCTYPE html>
<html>
<head><title>Invalid Link</title></head>
<body style="font-family: Arial, sans-serif; text-align: center; padding: 50px;">
    <h1>Invalid Verification Link</h1>
    <p>The verification link is invalid or has expired.</p>
</body>
</html>"#,
            )
            .into_response();
        }
    };

    // Check User-Agent for mobile detection
    let user_agent = headers
        .get(axum::http::header::USER_AGENT)
        .and_then(|v| v.to_str().ok())
        .unwrap_or("");

    let is_mobile = user_agent.contains("Android")
        || user_agent.contains("iPhone")
        || user_agent.contains("iPad")
        || user_agent.contains("Mobile");

    if is_mobile {
        // Mobile: Redirect to mobile app deep link
        let deep_link = format!(
            "{}verify-email?token={}",
            state.config.mobile_deep_link_scheme, token
        );
        tracing::debug!("Redirecting mobile user to deep link: {}", deep_link);
        Redirect::temporary(&deep_link).into_response()
    } else {
        // Desktop: Redirect to web frontend with token
        let web_url = format!(
            "{}/verify-email?token={}",
            state.config.web_frontend_url.trim_end_matches('/'),
            token
        );
        tracing::debug!("Redirecting desktop user to web frontend: {}", web_url);
        Redirect::temporary(&web_url).into_response()
    }
}
