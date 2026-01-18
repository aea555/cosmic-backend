//! Email verification token repository for database operations.
//!
//! This module handles all database queries related to email verification tokens.

use crate::error::{AppError, AppResult};
use crate::types::EmailVerificationToken;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Creates a new email verification token.
///
/// Params: Database pool, user UUID, token hash, expiration time.
/// Logic: Inserts new verification token record.
/// Returns: The created token record.
pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> AppResult<EmailVerificationToken> {
    sqlx::query_as::<_, EmailVerificationToken>(
        "INSERT INTO email_verification_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)
         RETURNING id, user_id, token_hash, expires_at, created_at",
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Finds a verification token by its hash.
///
/// Params: Database pool, token hash bytes.
/// Logic: Looks up token by hash.
/// Returns: Token if found, InvalidVerificationToken error otherwise.
pub async fn find_by_hash(pool: &PgPool, token_hash: &[u8]) -> AppResult<EmailVerificationToken> {
    sqlx::query_as::<_, EmailVerificationToken>(
        "SELECT id, user_id, token_hash, expires_at, created_at
         FROM email_verification_tokens
         WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::InvalidVerificationToken)
}

/// Deletes a verification token by ID.
///
/// Params: Database pool, token UUID.
/// Logic: Removes token after successful verification.
/// Returns: Unit on success.
pub async fn delete(pool: &PgPool, id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM email_verification_tokens WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Deletes all verification tokens for a user.
///
/// Params: Database pool, user UUID.
/// Logic: Cleanup after successful verification or for resending.
/// Returns: Unit on success.
pub async fn delete_all_for_user(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM email_verification_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Finds an active (non-expired) verification token for a user.
///
/// Params: Database pool, user UUID.
/// Logic: Returns the token if it exists and hasn't expired yet.
/// Returns: Some(token) if active token exists, None otherwise.
pub async fn find_active_for_user(
    pool: &PgPool,
    user_id: Uuid,
) -> AppResult<Option<EmailVerificationToken>> {
    sqlx::query_as::<_, EmailVerificationToken>(
        "SELECT id, user_id, token_hash, expires_at, created_at
         FROM email_verification_tokens
         WHERE user_id = $1 AND expires_at > NOW()
         ORDER BY created_at DESC
         LIMIT 1",
    )
    .bind(user_id)
    .fetch_optional(pool)
    .await
    .map_err(AppError::Database)
}
