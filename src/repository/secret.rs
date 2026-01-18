//! Secret repository for database operations.
//!
//! This module handles all database queries related to encrypted secrets.
//! All data stored is encrypted with the user's Master Key.

use crate::error::{AppError, AppResult};
use crate::types::Secret;
use sqlx::PgPool;
use uuid::Uuid;

/// Finds all secrets for a user.
///
/// Params: Database pool reference, user UUID.
/// Logic: Fetches all encrypted secret records for the user.
/// Returns: Vector of Secret records (still encrypted).
pub async fn find_all_by_user(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<Secret>> {
    let secrets = sqlx::query_as::<_, Secret>(
        "SELECT id, user_id, encrypted_data, created_at, updated_at
         FROM secrets
         WHERE user_id = $1
         ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(secrets)
}

/// Finds a specific secret by ID and user.
///
/// Params: Database pool, secret UUID, user UUID.
/// Logic: Fetches single secret, ensuring user ownership.
/// Returns: Secret if found and owned by user, SecretNotFound otherwise.
pub async fn find_by_id(pool: &PgPool, secret_id: Uuid, user_id: Uuid) -> AppResult<Secret> {
    sqlx::query_as::<_, Secret>(
        "SELECT id, user_id, encrypted_data, created_at, updated_at
         FROM secrets
         WHERE id = $1 AND user_id = $2",
    )
    .bind(secret_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::SecretNotFound)
}

/// Creates a new encrypted secret for a user.
///
/// Params: Database pool, user UUID, encrypted data bytes.
/// Logic: Inserts new secret record with encrypted data.
/// Returns: The created Secret record.
pub async fn create(pool: &PgPool, user_id: Uuid, encrypted_data: &[u8]) -> AppResult<Secret> {
    sqlx::query_as::<_, Secret>(
        "INSERT INTO secrets (user_id, encrypted_data)
         VALUES ($1, $2)
         RETURNING id, user_id, encrypted_data, created_at, updated_at",
    )
    .bind(user_id)
    .bind(encrypted_data)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Updates an existing secret's encrypted data.
///
/// Params: Database pool, secret UUID, user UUID, new encrypted data.
/// Logic: Updates encrypted_data, ensuring user ownership.
/// Returns: Updated Secret record, SecretNotFound if not found or not owned.
pub async fn update(
    pool: &PgPool,
    secret_id: Uuid,
    user_id: Uuid,
    encrypted_data: &[u8],
) -> AppResult<Secret> {
    sqlx::query_as::<_, Secret>(
        "UPDATE secrets
         SET encrypted_data = $1, updated_at = NOW()
         WHERE id = $2 AND user_id = $3
         RETURNING id, user_id, encrypted_data, created_at, updated_at",
    )
    .bind(encrypted_data)
    .bind(secret_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::SecretNotFound)
}

/// Deletes a secret by ID and user.
///
/// Params: Database pool, secret UUID, user UUID.
/// Logic: Removes secret, ensuring user ownership.
/// Returns: True if deleted, false if not found.
pub async fn delete(pool: &PgPool, secret_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let result = sqlx::query("DELETE FROM secrets WHERE id = $1 AND user_id = $2")
        .bind(secret_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}
