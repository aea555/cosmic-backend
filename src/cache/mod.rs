//! Cache layer for Valkey/Redis operations.
//!
//! This module provides caching for encrypted data. All data stored in cache
//! is encrypted - if the cache is compromised, attackers see only random bytes.

use crate::error::{AppError, AppResult};
use deadpool_redis::{Pool, redis::AsyncCommands};
use uuid::Uuid;

/// Default TTL for canary cache (1 hour).
const CANARY_TTL_SECONDS: u64 = 3600;

/// Default TTL for secrets cache (1 hour).
const SECRETS_TTL_SECONDS: u64 = 3600;

/// Default TTL for notes cache (1 hour).
const NOTES_TTL_SECONDS: u64 = 3600;

/// Default TTL for token blacklist (matches refresh token expiry).
const BLACKLIST_TTL_SECONDS: u64 = 30 * 24 * 3600;

/// Gets the encrypted canary from cache.
///
/// Params: Redis pool, user UUID.
/// Logic: Looks up cached canary blob.
/// Returns: Encrypted canary bytes if found, None otherwise.
pub async fn get_canary(pool: &Pool, user_id: Uuid) -> AppResult<Option<Vec<u8>>> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:canary", user_id);
    let result: Option<Vec<u8>> = conn.get(&key).await?;

    Ok(result)
}

/// Caches the encrypted canary.
///
/// Params: Redis pool, user UUID, encrypted canary bytes.
/// Logic: Stores encrypted blob with TTL.
/// Returns: Unit on success.
pub async fn set_canary(pool: &Pool, user_id: Uuid, canary: &[u8]) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:canary", user_id);
    let _: () = conn.set_ex(&key, canary, CANARY_TTL_SECONDS).await?;

    Ok(())
}

/// Gets the encrypted secrets list from cache.
///
/// Params: Redis pool, user UUID.
/// Logic: Looks up cached encrypted secrets blob.
/// Returns: Serialized encrypted secrets if found, None otherwise.
pub async fn get_secrets(pool: &Pool, user_id: Uuid) -> AppResult<Option<Vec<u8>>> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:secrets", user_id);
    let result: Option<Vec<u8>> = conn.get(&key).await?;

    Ok(result)
}

/// Caches the encrypted secrets list.
///
/// Params: Redis pool, user UUID, serialized encrypted secrets.
/// Logic: Stores encrypted blob with TTL.
/// Returns: Unit on success.
pub async fn set_secrets(pool: &Pool, user_id: Uuid, secrets: &[u8]) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:secrets", user_id);
    let _: () = conn.set_ex(&key, secrets, SECRETS_TTL_SECONDS).await?;

    Ok(())
}

/// Invalidates the secrets cache for a user.
///
/// Params: Redis pool, user UUID.
/// Logic: Deletes cached secrets. Called after write operations.
/// Returns: Unit on success.
pub async fn invalidate_secrets(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:secrets", user_id);
    let _: () = conn.del(&key).await?;

    Ok(())
}

/// Gets the encrypted notes list from cache.
///
/// Params: Redis pool, user UUID.
/// Logic: Looks up cached encrypted notes blob.
/// Returns: Serialized encrypted notes if found, None otherwise.
pub async fn get_notes(pool: &Pool, user_id: Uuid) -> AppResult<Option<Vec<u8>>> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:notes", user_id);
    let result: Option<Vec<u8>> = conn.get(&key).await?;

    Ok(result)
}

/// Caches the encrypted notes list.
///
/// Params: Redis pool, user UUID, serialized encrypted notes.
/// Logic: Stores encrypted blob with TTL.
/// Returns: Unit on success.
pub async fn set_notes(pool: &Pool, user_id: Uuid, notes: &[u8]) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:notes", user_id);
    let _: () = conn.set_ex(&key, notes, NOTES_TTL_SECONDS).await?;

    Ok(())
}

/// Invalidates the notes cache for a user.
///
/// Params: Redis pool, user UUID.
/// Logic: Deletes cached notes. Called after write operations.
/// Returns: Unit on success.
pub async fn invalidate_notes(pool: &Pool, user_id: Uuid) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("user:{}:notes", user_id);
    let _: () = conn.del(&key).await?;

    Ok(())
}

// ----------------------------------------------------------------------------
// SINGLE ENTITY CACHE (by ID)
// ----------------------------------------------------------------------------

/// Gets a single encrypted secret from cache.
///
/// Params: Redis pool, secret UUID.
/// Logic: Looks up cached secret blob by ID.
/// Returns: Serialized encrypted secret if found, None otherwise.
pub async fn get_secret_by_id(pool: &Pool, secret_id: Uuid) -> AppResult<Option<Vec<u8>>> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("secret:{}", secret_id);
    let result: Option<Vec<u8>> = conn.get(&key).await?;

    Ok(result)
}

/// Caches a single encrypted secret.
///
/// Params: Redis pool, secret UUID, serialized encrypted secret.
/// Logic: Stores encrypted blob with TTL.
/// Returns: Unit on success.
pub async fn set_secret_by_id(pool: &Pool, secret_id: Uuid, secret: &[u8]) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("secret:{}", secret_id);
    let _: () = conn.set_ex(&key, secret, SECRETS_TTL_SECONDS).await?;

    Ok(())
}

/// Invalidates a single secret from cache.
///
/// Params: Redis pool, secret UUID.
/// Logic: Deletes cached secret. Called after update/delete.
/// Returns: Unit on success.
pub async fn invalidate_secret_by_id(pool: &Pool, secret_id: Uuid) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("secret:{}", secret_id);
    let _: () = conn.del(&key).await?;

    Ok(())
}

/// Gets a single encrypted note from cache.
///
/// Params: Redis pool, note UUID.
/// Logic: Looks up cached note blob by ID.
/// Returns: Serialized encrypted note if found, None otherwise.
pub async fn get_note_by_id(pool: &Pool, note_id: Uuid) -> AppResult<Option<Vec<u8>>> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("note:{}", note_id);
    let result: Option<Vec<u8>> = conn.get(&key).await?;

    Ok(result)
}

/// Caches a single encrypted note.
///
/// Params: Redis pool, note UUID, serialized encrypted note.
/// Logic: Stores encrypted blob with TTL.
/// Returns: Unit on success.
pub async fn set_note_by_id(pool: &Pool, note_id: Uuid, note: &[u8]) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("note:{}", note_id);
    let _: () = conn.set_ex(&key, note, NOTES_TTL_SECONDS).await?;

    Ok(())
}

/// Invalidates a single note from cache.
///
/// Params: Redis pool, note UUID.
/// Logic: Deletes cached note. Called after update/delete.
/// Returns: Unit on success.
pub async fn invalidate_note_by_id(pool: &Pool, note_id: Uuid) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("note:{}", note_id);
    let _: () = conn.del(&key).await?;

    Ok(())
}

/// Checks if a refresh token is blacklisted.
///
/// Params: Redis pool, token hash bytes.
/// Logic: Looks up token in blacklist.
/// Returns: True if blacklisted, false otherwise.
pub async fn is_token_blacklisted(pool: &Pool, token_hash: &[u8]) -> AppResult<bool> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("blacklist:{}", hex::encode(token_hash));
    let exists: bool = conn.exists(&key).await?;

    Ok(exists)
}

/// Adds a refresh token to the blacklist.
///
/// Params: Redis pool, token hash bytes.
/// Logic: Stores token hash with TTL matching refresh token expiry.
/// Returns: Unit on success.
pub async fn blacklist_token(pool: &Pool, token_hash: &[u8]) -> AppResult<()> {
    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to get Redis connection: {}", e)))?;

    let key = format!("blacklist:{}", hex::encode(token_hash));
    let _: () = conn.set_ex(&key, "1", BLACKLIST_TTL_SECONDS).await?;

    Ok(())
}
