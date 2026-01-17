//! Vault logic for secret management.
//!
//! This module handles encryption/decryption of user secrets. All operations
//! require the Master Key to be provided and verified before use.

use crate::core::crypto;
use crate::error::{AppError, AppResult};
use crate::repository;
use crate::types::{
    CreateSecretRequest, EncryptedBlob, MasterKey, Secret, SecretId, SecretResponse,
    UpdateSecretRequest,
};
use rayon::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

/// Creates a new encrypted secret.
///
/// Params: Database pool, user ID, secret data, Master Key.
/// Logic: Serializes and encrypts secret data, stores encrypted blob.
/// Returns: The created SecretResponse.
///
/// # Errors
/// Returns error if encryption or database operation fails.
pub async fn create_secret(
    pool: &PgPool,
    user_id: Uuid,
    request: CreateSecretRequest,
    key: &MasterKey,
) -> AppResult<SecretResponse> {
    // Serialize the secret data
    let json_data = serde_json::to_vec(&request)
        .map_err(|e| AppError::Internal(format!("Failed to serialize secret: {}", e)))?;

    // Encrypt the data
    let encrypted = crypto::encrypt(&json_data, key)?;

    // Store in database
    let secret = repository::secret::create(pool, user_id, encrypted.as_bytes()).await?;

    build_secret_response(secret, request)
}

/// Updates an existing secret.
///
/// Params: Database pool, secret ID, user ID, updated data, Master Key.
/// Logic: Re-encrypts secret data, updates database record.
/// Returns: The updated SecretResponse.
///
/// # Errors
/// Returns error if secret not found, encryption fails, or DB operation fails.
pub async fn update_secret(
    pool: &PgPool,
    secret_id: Uuid,
    user_id: Uuid,
    request: UpdateSecretRequest,
    key: &MasterKey,
) -> AppResult<SecretResponse> {
    // Verify secret exists and belongs to user
    repository::secret::find_by_id(pool, secret_id, user_id).await?;

    // Serialize and encrypt
    let json_data = serde_json::to_vec(&request)
        .map_err(|e| AppError::Internal(format!("Failed to serialize secret: {}", e)))?;
    let encrypted = crypto::encrypt(&json_data, key)?;

    // Update in database
    let secret = repository::secret::update(pool, secret_id, user_id, encrypted.as_bytes()).await?;

    Ok(SecretResponse {
        id: SecretId(secret.id),
        title: request.title,
        username: request.username,
        password: request.password,
        notes: request.notes,
        url: request.url,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    })
}

/// Deletes a secret.
///
/// Params: Database pool, secret ID, user ID.
/// Logic: Removes secret from database.
/// Returns: True if deleted, error if not found.
///
/// # Errors
/// Returns SecretNotFound if secret doesn't exist or user doesn't own it.
pub async fn delete_secret(pool: &PgPool, secret_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let deleted = repository::secret::delete(pool, secret_id, user_id).await?;
    if !deleted {
        return Err(AppError::SecretNotFound);
    }
    Ok(())
}

/// Gets a single decrypted secret.
///
/// Params: Database pool, secret ID, user ID, Master Key.
/// Logic: Fetches encrypted secret, decrypts with Master Key.
/// Returns: Decrypted SecretResponse.
///
/// # Errors
/// Returns error if secret not found or decryption fails.
pub async fn get_secret(
    pool: &PgPool,
    secret_id: Uuid,
    user_id: Uuid,
    key: &MasterKey,
) -> AppResult<SecretResponse> {
    let secret = repository::secret::find_by_id(pool, secret_id, user_id).await?;
    decrypt_secret_to_response(secret, key)
}

/// Gets all decrypted secrets for a user.
///
/// Params: Database pool, user ID, Master Key.
/// Logic: Fetches all encrypted secrets, decrypts in parallel using Rayon.
/// Returns: Vector of decrypted SecretResponses.
///
/// # Errors
/// Returns error if database operation or decryption fails.
pub async fn get_all_secrets(
    pool: &PgPool,
    user_id: Uuid,
    key: MasterKey,
) -> AppResult<Vec<SecretResponse>> {
    let secrets = repository::secret::find_all_by_user(pool, user_id).await?;

    if secrets.is_empty() {
        return Ok(Vec::new());
    }

    // Decrypt in parallel using Rayon (in blocking task to not block async runtime)
    tokio::task::spawn_blocking(move || {
        let results: Vec<AppResult<SecretResponse>> = secrets
            .into_par_iter()
            .map(|secret| decrypt_secret_to_response(secret, &key))
            .collect();

        // Collect results, failing on first error
        results.into_iter().collect()
    })
    .await
    .map_err(|e| AppError::Internal(format!("Blocking task failed: {}", e)))?
}

/// Decrypts a Secret entity to a SecretResponse.
///
/// Params: Secret entity with encrypted data, Master Key.
/// Logic: Decrypts and deserializes the JSON payload.
/// Returns: Decrypted SecretResponse.
fn decrypt_secret_to_response(secret: Secret, key: &MasterKey) -> AppResult<SecretResponse> {
    let encrypted = EncryptedBlob::new(secret.encrypted_data);
    let decrypted = crypto::decrypt(&encrypted, key)?;

    let data: CreateSecretRequest = serde_json::from_slice(&decrypted)
        .map_err(|e| AppError::Internal(format!("Failed to deserialize secret: {}", e)))?;

    Ok(SecretResponse {
        id: SecretId(secret.id),
        title: data.title,
        username: data.username,
        password: data.password,
        notes: data.notes,
        url: data.url,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    })
}

/// Builds a SecretResponse from a Secret entity and the original request.
///
/// Params: Secret entity, original create request.
/// Logic: Combines database metadata with request data.
/// Returns: Complete SecretResponse.
fn build_secret_response(
    secret: Secret,
    request: CreateSecretRequest,
) -> AppResult<SecretResponse> {
    Ok(SecretResponse {
        id: SecretId(secret.id),
        title: request.title,
        username: request.username,
        password: request.password,
        notes: request.notes,
        url: request.url,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    })
}
