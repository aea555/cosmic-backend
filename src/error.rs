//! Application error types with HTTP response mapping.
//!
//! This module defines a unified error type that maps domain errors to appropriate
//! HTTP status codes and response bodies. All errors are logged server-side with
//! full details while returning sanitized messages to clients.

use axum::{
    Json,
    http::StatusCode,
    response::{IntoResponse, Response},
};
use serde::Serialize;
use thiserror::Error;

/// Application error type covering all possible failure modes.
///
/// Each variant maps to a specific HTTP status code. Internal details are logged
/// but not exposed to clients to prevent information leakage.
#[derive(Debug, Error)]
pub enum AppError {
    /// Input validation failed.
    #[error("Validation error: {0}")]
    Validation(String),

    /// Invalid email or password during login.
    #[error("Invalid credentials")]
    InvalidCredentials,

    /// JWT token is invalid, expired, or malformed.
    #[error("Invalid token")]
    InvalidToken,

    /// Refresh token was already used (potential attack).
    #[error("Token has been reused")]
    TokenReused,

    /// Refresh token has expired.
    #[error("Token has expired")]
    TokenExpired,

    /// Email not yet verified.
    #[error("Email not verified")]
    EmailNotVerified,

    /// Verification token is invalid or expired.
    #[error("Invalid verification token")]
    InvalidVerificationToken,

    /// User not found in database.
    #[error("User not found")]
    UserNotFound,

    /// Secret not found in database.
    #[error("Secret not found")]
    SecretNotFound,

    /// Email already registered.
    #[error("User already exists")]
    UserAlreadyExists,

    /// Email is already verified.
    #[error("Email already verified")]
    EmailAlreadyVerified,

    /// Verification email recently sent, must wait before resending.
    #[error("Verification pending")]
    VerificationPending {
        /// Seconds until a new verification email can be requested.
        retry_after_seconds: i64,
    },

    /// Master password header missing from request.
    #[error("Master password required")]
    MasterPasswordRequired,

    /// Rate limit exceeded.
    #[error("Rate limit exceeded")]
    RateLimited {
        /// Seconds until the rate limit resets.
        retry_after_seconds: u64,
    },

    /// Database operation failed.
    #[error("Database error: {0}")]
    Database(#[from] sqlx::Error),

    /// Redis/Valkey operation failed.
    #[error("Cache error: {0}")]
    Redis(#[from] redis::RedisError),

    /// Cryptographic operation failed.
    #[error("Cryptographic error: {0}")]
    Crypto(String),

    /// Email sending failed.
    #[error("Email error: {0}")]
    Email(String),

    /// Internal server error (catch-all).
    #[error("Internal error: {0}")]
    Internal(String),

    /// JSON parsing/deserialization failed.
    #[error("Invalid request body")]
    JsonParsing(String),

    /// OTP is invalid or expired.
    #[error("Invalid OTP")]
    InvalidOtp,
}

/// Error response body sent to clients.
///
/// Internal error details are never included.
#[derive(Debug, Serialize)]
struct ErrorResponse {
    success: bool,
    error: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    code: Option<String>,
}

impl IntoResponse for AppError {
    /// Converts the application error into an HTTP response.
    ///
    /// Params: Self.
    /// Logic: Maps error variants to HTTP status codes and sanitizes messages.
    /// Returns: HTTP response with JSON body.
    fn into_response(self) -> Response {
        let (status, code, message) = match &self {
            // 400 Bad Request
            AppError::Validation(msg) => (StatusCode::BAD_REQUEST, "VALIDATION_ERROR", msg.clone()),

            // 401 Unauthorized
            AppError::InvalidCredentials => (
                StatusCode::UNAUTHORIZED,
                "INVALID_CREDENTIALS",
                "Invalid email or password".to_string(),
            ),
            AppError::InvalidToken => (
                StatusCode::UNAUTHORIZED,
                "INVALID_TOKEN",
                "Token is invalid or expired".to_string(),
            ),
            AppError::MasterPasswordRequired => (
                StatusCode::UNAUTHORIZED,
                "MASTER_PASSWORD_REQUIRED",
                "X-Master-Password header is required".to_string(),
            ),

            // 403 Forbidden
            AppError::TokenReused => (
                StatusCode::FORBIDDEN,
                "TOKEN_REUSED",
                "Token has been reused - possible security breach".to_string(),
            ),
            AppError::TokenExpired => (
                StatusCode::FORBIDDEN,
                "TOKEN_EXPIRED",
                "Token has expired".to_string(),
            ),
            AppError::EmailNotVerified => (
                StatusCode::FORBIDDEN,
                "EMAIL_NOT_VERIFIED",
                "Please verify your email before logging in".to_string(),
            ),
            AppError::InvalidVerificationToken => (
                StatusCode::FORBIDDEN,
                "INVALID_VERIFICATION_TOKEN",
                "Verification token is invalid or expired".to_string(),
            ),

            // 404 Not Found
            AppError::UserNotFound => (
                StatusCode::NOT_FOUND,
                "USER_NOT_FOUND",
                "User not found".to_string(),
            ),
            AppError::SecretNotFound => (
                StatusCode::NOT_FOUND,
                "SECRET_NOT_FOUND",
                "Secret not found".to_string(),
            ),

            // 409 Conflict
            AppError::UserAlreadyExists => (
                StatusCode::CONFLICT,
                "USER_EXISTS",
                "An account with this email already exists".to_string(),
            ),
            AppError::EmailAlreadyVerified => (
                StatusCode::CONFLICT,
                "EMAIL_ALREADY_VERIFIED",
                "This email address is already verified".to_string(),
            ),

            // 429 Too Many Requests
            AppError::VerificationPending {
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "VERIFICATION_PENDING",
                format!(
                    "A verification email was recently sent. Please wait {} seconds before requesting a new one.",
                    retry_after_seconds
                ),
            ),

            // 429 Too Many Requests
            AppError::RateLimited {
                retry_after_seconds,
            } => (
                StatusCode::TOO_MANY_REQUESTS,
                "RATE_LIMITED",
                format!(
                    "Rate limit exceeded. Retry after {} seconds.",
                    retry_after_seconds
                ),
            ),

            // 500 Internal Server Error
            AppError::Database(e) => {
                tracing::error!("Database error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "DATABASE_ERROR",
                    "An internal error occurred".to_string(),
                )
            }
            AppError::Redis(e) => {
                tracing::error!("Redis error: {:?}", e);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CACHE_ERROR",
                    "An internal error occurred".to_string(),
                )
            }
            AppError::Crypto(msg) => {
                tracing::error!("Crypto error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "CRYPTO_ERROR",
                    "An internal error occurred".to_string(),
                )
            }
            AppError::Email(msg) => {
                tracing::error!("Email error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "EMAIL_ERROR",
                    "Failed to send email".to_string(),
                )
            }
            AppError::Internal(msg) => {
                tracing::error!("Internal error: {}", msg);
                (
                    StatusCode::INTERNAL_SERVER_ERROR,
                    "INTERNAL_ERROR",
                    "An internal error occurred".to_string(),
                )
            }

            // 422 Unprocessable Entity
            AppError::JsonParsing(msg) => {
                tracing::debug!("JSON parsing error: {}", msg);
                (
                    StatusCode::UNPROCESSABLE_ENTITY,
                    "INVALID_REQUEST_BODY",
                    "Invalid request body format".to_string(),
                )
            }

            // 401 Unauthorized - Invalid OTP
            AppError::InvalidOtp => (
                StatusCode::UNAUTHORIZED,
                "INVALID_OTP",
                "OTP is invalid or expired".to_string(),
            ),
        };

        let body = ErrorResponse {
            success: false,
            error: message,
            code: Some(code.to_string()),
        };

        (status, Json(body)).into_response()
    }
}

/// Result type alias using AppError.
pub type AppResult<T> = Result<T, AppError>;

// ----------------------------------------------------------------------------
// Custom JSON Extractor
// ----------------------------------------------------------------------------

use axum::extract::{FromRequest, Request, rejection::JsonRejection};

/// Custom JSON extractor that converts Axum's JsonRejection into AppError.
///
/// Params: Wraps the request body as type T.
/// Logic: Intercepts JSON parsing failures and returns sanitized error messages.
/// Returns: Parsed JSON or AppError::JsonParsing.
pub struct AppJson<T>(pub T);

impl<S, T> FromRequest<S> for AppJson<T>
where
    axum::Json<T>: FromRequest<S, Rejection = JsonRejection>,
    S: Send + Sync,
{
    type Rejection = AppError;

    async fn from_request(req: Request, state: &S) -> Result<Self, Self::Rejection> {
        match axum::Json::<T>::from_request(req, state).await {
            Ok(value) => Ok(AppJson(value.0)),
            Err(rejection) => {
                // Log the full error for debugging, return sanitized message
                Err(AppError::JsonParsing(rejection.body_text()))
            }
        }
    }
}
