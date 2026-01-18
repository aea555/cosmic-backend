//! Refresh token repository for database operations.
//!
//! This module handles all database queries related to refresh tokens.
//! Tokens are stored as SHA-256 hashes for security.

use crate::error::{AppError, AppResult};
use crate::types::RefreshToken;
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

/// Creates a new refresh token record.
///
/// Params: Database pool, user UUID, token hash bytes, expiration time.
/// Logic: Inserts new refresh token with used = false.
/// Returns: The created RefreshToken record.
pub async fn create(
    pool: &PgPool,
    user_id: Uuid,
    token_hash: &[u8],
    expires_at: DateTime<Utc>,
) -> AppResult<RefreshToken> {
    sqlx::query_as::<_, RefreshToken>(
        "INSERT INTO refresh_tokens (user_id, token_hash, expires_at)
         VALUES ($1, $2, $3)
         RETURNING id, user_id, token_hash, used, expires_at, created_at",
    )
    .bind(user_id)
    .bind(token_hash)
    .bind(expires_at)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Finds a refresh token by its hash.
///
/// Params: Database pool, token hash bytes.
/// Logic: Looks up token record by hash.
/// Returns: RefreshToken if found, InvalidToken error otherwise.
pub async fn find_by_hash(pool: &PgPool, token_hash: &[u8]) -> AppResult<RefreshToken> {
    sqlx::query_as::<_, RefreshToken>(
        "SELECT id, user_id, token_hash, used, expires_at, created_at
         FROM refresh_tokens
         WHERE token_hash = $1",
    )
    .bind(token_hash)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::InvalidToken)
}

/// Marks a refresh token as used.
///
/// Params: Database pool, token UUID.
/// Logic: Sets used = true for rotation tracking.
/// Returns: Unit on success.
pub async fn mark_used(pool: &PgPool, id: Uuid) -> AppResult<()> {
    sqlx::query("UPDATE refresh_tokens SET used = true WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Revokes all refresh tokens for a user (token family revocation).
///
/// Params: Database pool, user UUID.
/// Logic: Deletes all refresh tokens for the user. Used on security breach detection.
/// Returns: Number of tokens revoked.
pub async fn revoke_all_for_user(pool: &PgPool, user_id: Uuid) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}

/// Deletes a specific refresh token.
///
/// Params: Database pool, token UUID.
/// Logic: Removes single token record.
/// Returns: Unit on success.
pub async fn delete(pool: &PgPool, id: Uuid) -> AppResult<()> {
    sqlx::query("DELETE FROM refresh_tokens WHERE id = $1")
        .bind(id)
        .execute(pool)
        .await?;

    Ok(())
}

/// Cleans up expired refresh tokens.
///
/// Params: Database pool.
/// Logic: Deletes all tokens where expires_at < NOW().
/// Returns: Number of tokens deleted.
#[allow(dead_code)] // Useful for scheduled cleanup jobs
pub async fn cleanup_expired(pool: &PgPool) -> AppResult<u64> {
    let result = sqlx::query("DELETE FROM refresh_tokens WHERE expires_at < NOW()")
        .execute(pool)
        .await?;

    Ok(result.rows_affected())
}
