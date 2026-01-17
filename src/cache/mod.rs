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
#[allow(dead_code)] // Optional: for future read-through caching
const SECRETS_TTL_SECONDS: u64 = 3600;

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
#[allow(dead_code)] // Optional: for future read-through caching
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
#[allow(dead_code)] // Optional: for future read-through caching
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
