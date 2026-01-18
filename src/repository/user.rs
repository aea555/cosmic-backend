//! User repository for database operations.
//!
//! This module handles all database queries related to users.
//! No business logic belongs here - only data access.

use crate::error::{AppError, AppResult};
use crate::types::User;
use sqlx::PgPool;
use uuid::Uuid;

/// Checks if a user with the given email already exists.
///
/// Params: Database pool reference, email string.
/// Logic: Performs existence check using SELECT 1 for efficiency.
/// Returns: True if user exists, false otherwise.
pub async fn exists_by_email(pool: &PgPool, email: &str) -> AppResult<bool> {
    let result: Option<(i32,)> = sqlx::query_as("SELECT 1 FROM users WHERE email = $1")
        .bind(email)
        .fetch_optional(pool)
        .await?;

    Ok(result.is_some())
}

/// Finds a user by email address.
///
/// Params: Database pool reference, email string.
/// Logic: Fetches complete user record including salt and encrypted canary.
/// Returns: User if found, UserNotFound error otherwise.
pub async fn find_by_email(pool: &PgPool, email: &str) -> AppResult<User> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, salt, encrypted_canary, email_verified, created_at, updated_at
         FROM users
         WHERE email = $1",
    )
    .bind(email)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::UserNotFound)
}

/// Finds a user by ID.
///
/// Params: Database pool reference, user UUID.
/// Logic: Fetches complete user record.
/// Returns: User if found, UserNotFound error otherwise.
pub async fn find_by_id(pool: &PgPool, id: Uuid) -> AppResult<User> {
    sqlx::query_as::<_, User>(
        "SELECT id, email, salt, encrypted_canary, email_verified, created_at, updated_at
         FROM users
         WHERE id = $1",
    )
    .bind(id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::UserNotFound)
}

/// Creates a new user with their salt and encrypted canary.
///
/// Params: Database pool, email, salt bytes, encrypted canary bytes.
/// Logic: Inserts new user record. Email uniqueness enforced by DB constraint.
/// Returns: The created User record.
pub async fn create(
    pool: &PgPool,
    email: &str,
    salt: &[u8],
    encrypted_canary: &[u8],
) -> AppResult<User> {
    sqlx::query_as::<_, User>(
        "INSERT INTO users (email, salt, encrypted_canary)
         VALUES ($1, $2, $3)
         RETURNING id, email, salt, encrypted_canary, email_verified, created_at, updated_at",
    )
    .bind(email)
    .bind(salt)
    .bind(encrypted_canary)
    .fetch_one(pool)
    .await
    .map_err(|e| {
        if let sqlx::Error::Database(ref db_err) = e {
            if db_err.is_unique_violation() {
                return AppError::UserAlreadyExists;
            }
        }
        AppError::Database(e)
    })
}

/// Marks a user's email as verified.
///
/// Params: Database pool, user UUID.
/// Logic: Updates email_verified flag to true.
/// Returns: Unit on success, error on failure.
pub async fn mark_email_verified(pool: &PgPool, user_id: Uuid) -> AppResult<()> {
    sqlx::query(
        "UPDATE users
         SET email_verified = true, updated_at = NOW()
         WHERE id = $1",
    )
    .bind(user_id)
    .execute(pool)
    .await?;

    Ok(())
}
