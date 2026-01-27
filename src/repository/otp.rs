//! OTP repository for database operations.
//!
//! This module handles OTP requests for sensitive operations like
//! account deletion, password change, and email change.

use crate::error::{AppError, AppResult};
use crate::types::OtpRequest;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Creates a new OTP request.
///
/// Params: Database pool, user UUID, OTP hash, request type, optional new email, expiry time.
/// Logic: Inserts new OTP request, deleting any existing request of same type for user.
/// Returns: The created OtpRequest record.
pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    otp_hash: &[u8],
    request_type: &str,
    new_email: Option<&str>,
    expires_at: DateTime<Utc>,
) -> AppResult<OtpRequest> {
    // Delete any existing request of same type for this user
    sqlx::query("DELETE FROM otp_requests WHERE user_id = $1 AND request_type = $2")
        .bind(user_id)
        .bind(request_type)
        .execute(pool)
        .await?;

    // Create new request
    sqlx::query_as::<_, OtpRequest>(
        "INSERT INTO otp_requests (user_id, otp_hash, request_type, new_email, expires_at)
         VALUES ($1, $2, $3, $4, $5)
         RETURNING id, user_id, otp_hash, request_type, new_email, expires_at, created_at",
    )
    .bind(user_id)
    .bind(otp_hash)
    .bind(request_type)
    .bind(new_email)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Finds a valid (non-expired) OTP request for a user and type.
///
/// Params: Database pool, user UUID, request type.
/// Logic: Fetches unexpired OTP request.
/// Returns: OtpRequest if found and valid, None otherwise.
pub async fn find_valid(
    pool: &PgPool,
    user_id: Uuid,
    request_type: &str,
) -> AppResult<Option<OtpRequest>> {
    let result = sqlx::query_as::<_, OtpRequest>(
        "SELECT id, user_id, otp_hash, request_type, new_email, expires_at, created_at
         FROM otp_requests
         WHERE user_id = $1 AND request_type = $2 AND expires_at > NOW()",
    )
    .bind(user_id)
    .bind(request_type)
    .fetch_optional(pool)
    .await?;

    Ok(result)
}

/// Deletes all OTP requests for a user and type.
///
/// Params: Database pool, user UUID, request type.
/// Logic: Removes all matching OTP requests.
/// Returns: Unit on success.
pub async fn delete_for_user(pool: &PgPool, user_id: Uuid, request_type: &str) -> AppResult<()> {
    sqlx::query("DELETE FROM otp_requests WHERE user_id = $1 AND request_type = $2")
        .bind(user_id)
        .bind(request_type)
        .execute(pool)
        .await?;

    Ok(())
}

/// Deletes all OTP requests for a user (all types).
///
/// Params: Database pool, user UUID.
/// Logic: Removes all OTP requests for user.
/// Returns: Unit on success.
pub async fn delete_all_for_user(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM otp_requests WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}
