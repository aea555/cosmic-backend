//! Authentication HTTP handlers.
//!
//! This module contains the HTTP handlers for authentication endpoints.
//! Handlers are thin and delegate to core business logic.

use crate::core::auth;
use crate::error::{AppError, AppResult};
use crate::handlers::email;
use crate::state::AppState;
use crate::types::{
    ApiResponse, AuthResponse, AuthResponseWrapper, EmptyResponseWrapper, LoginRequest,
    RefreshRequest, RegisterRequest, VerifyEmailRequest,
};
use axum::{extract::State, http::StatusCode, Json};
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
    Json(request): Json<RegisterRequest>,
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
    Json(request): Json<VerifyEmailRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    auth::verify_email(&state.db, &request.token).await?;

    tracing::info!("Email verified successfully");

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Email verified successfully. You can now log in.".to_string()),
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
    Json(request): Json<LoginRequest>,
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
    Json(request): Json<RefreshRequest>,
) -> AppResult<Json<ApiResponse<AuthResponse>>> {
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
    Json(request): Json<RefreshRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    auth::logout(&state.db, &state.cache, &request.refresh_token).await?;

    tracing::debug!("User logged out");

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Logged out successfully".to_string()),
        data: None,
    }))
}
