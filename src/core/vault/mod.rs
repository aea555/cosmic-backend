//! Vault logic for secret management.
//!
//! This module handles encryption/decryption of user secrets and notes.
//! All operations require the Master Key to be provided and verified before use.

use crate::core::crypto;
use crate::error::{AppError, AppResult};
use crate::repository;
use crate::types::{
    CreateNoteRequest, CreateSecretRequest, EncryptedBlob, MasterKey, Note, NoteId, NoteResponse,
    Secret, SecretId, SecretResponse, UpdateNoteRequest, UpdateSecretRequest,
};
use rayon::prelude::*;
use sqlx::PgPool;
use uuid::Uuid;

// ----------------------------------------------------------------------------
// SECRETS
// ----------------------------------------------------------------------------

/// Creates a new encrypted secret.
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
        email: request.email,
        telephone_number: request.telephone_number,
        password: request.password,
        url: request.url,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    })
}

/// Deletes a secret.
pub async fn delete_secret(pool: &PgPool, secret_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let deleted = repository::secret::delete(pool, secret_id, user_id).await?;
    if !deleted {
        return Err(AppError::SecretNotFound);
    }
    Ok(())
}

/// Gets a single decrypted secret.
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
pub async fn get_all_secrets(
    pool: &PgPool,
    user_id: Uuid,
    key: MasterKey,
) -> AppResult<Vec<SecretResponse>> {
    let secrets = repository::secret::find_all_by_user(pool, user_id).await?;

    if secrets.is_empty() {
        return Ok(Vec::new());
    }

    // Decrypt in parallel using Rayon (in blocking task)
    tokio::task::spawn_blocking(move || {
        let results: Vec<AppResult<SecretResponse>> = secrets
            .into_par_iter()
            .map(|secret| decrypt_secret_to_response(secret, &key))
            .collect();

        results.into_iter().collect()
    })
    .await
    .map_err(|e| AppError::Internal(format!("Blocking task failed: {}", e)))?
}

// ----------------------------------------------------------------------------
// NOTES
// ----------------------------------------------------------------------------

/// Creates a new encrypted note.
pub async fn create_note(
    pool: &PgPool,
    user_id: Uuid,
    request: CreateNoteRequest,
    key: &MasterKey,
) -> AppResult<NoteResponse> {
    let json_data = serde_json::to_vec(&request)
        .map_err(|e| AppError::Internal(format!("Failed to serialize note: {}", e)))?;

    let encrypted = crypto::encrypt(&json_data, key)?;

    let note = repository::note::create(pool, user_id, encrypted.as_bytes()).await?;

    build_note_response(note, request)
}

/// Updates an existing note.
pub async fn update_note(
    pool: &PgPool,
    note_id: Uuid,
    user_id: Uuid,
    request: UpdateNoteRequest,
    key: &MasterKey,
) -> AppResult<NoteResponse> {
    repository::note::find_by_id(pool, note_id, user_id).await?;

    let json_data = serde_json::to_vec(&request)
        .map_err(|e| AppError::Internal(format!("Failed to serialize note: {}", e)))?;
    let encrypted = crypto::encrypt(&json_data, key)?;

    let note = repository::note::update(pool, note_id, user_id, encrypted.as_bytes()).await?;

    Ok(NoteResponse {
        id: NoteId(note.id),
        title: request.title,
        content: request.content,
        created_at: note.created_at,
        updated_at: note.updated_at,
    })
}

/// Deletes a note.
pub async fn delete_note(pool: &PgPool, note_id: Uuid, user_id: Uuid) -> AppResult<()> {
    let deleted = repository::note::delete(pool, note_id, user_id).await?;
    if !deleted {
        return Err(AppError::SecretNotFound); // Generic error for now
    }
    Ok(())
}

/// Gets a single decrypted note.
pub async fn get_note(
    pool: &PgPool,
    note_id: Uuid,
    user_id: Uuid,
    key: &MasterKey,
) -> AppResult<NoteResponse> {
    let note = repository::note::find_by_id(pool, note_id, user_id).await?;
    decrypt_note_to_response(note, key)
}

/// Gets all decrypted notes for a user.
pub async fn get_all_notes(
    pool: &PgPool,
    user_id: Uuid,
    key: MasterKey,
) -> AppResult<Vec<NoteResponse>> {
    let notes = repository::note::find_all_by_user(pool, user_id).await?;

    if notes.is_empty() {
        return Ok(Vec::new());
    }

    tokio::task::spawn_blocking(move || {
        let results: Vec<AppResult<NoteResponse>> = notes
            .into_par_iter()
            .map(|note| decrypt_note_to_response(note, &key))
            .collect();

        results.into_iter().collect()
    })
    .await
    .map_err(|e| AppError::Internal(format!("Blocking task failed: {}", e)))?
}

// ----------------------------------------------------------------------------
// HELPERS
// ----------------------------------------------------------------------------

fn decrypt_secret_to_response(secret: Secret, key: &MasterKey) -> AppResult<SecretResponse> {
    let encrypted = EncryptedBlob::new(secret.encrypted_data);
    let decrypted = crypto::decrypt(&encrypted, key)?;

    // We try to deserialize into CreateSecretRequest structure which holds the plaintext data layout
    // existing data (with 'notes' field) might fail if deserialized into new struct strictly?
    // serde usually ignores unknown fields by default if not strict.
    // However, if we removed 'notes' field from struct, it will just drop it.
    let data: CreateSecretRequest = serde_json::from_slice(&decrypted)
        .map_err(|e| AppError::Internal(format!("Failed to deserialize secret: {}", e)))?;

    Ok(SecretResponse {
        id: SecretId(secret.id),
        title: data.title,
        username: data.username,
        email: data.email,
        telephone_number: data.telephone_number,
        password: data.password,
        url: data.url,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    })
}

fn build_secret_response(
    secret: Secret,
    request: CreateSecretRequest,
) -> AppResult<SecretResponse> {
    Ok(SecretResponse {
        id: SecretId(secret.id),
        title: request.title,
        username: request.username,
        email: request.email,
        telephone_number: request.telephone_number,
        password: request.password,
        url: request.url,
        created_at: secret.created_at,
        updated_at: secret.updated_at,
    })
}

fn decrypt_note_to_response(note: Note, key: &MasterKey) -> AppResult<NoteResponse> {
    let encrypted = EncryptedBlob::new(note.encrypted_data);
    let decrypted = crypto::decrypt(&encrypted, key)?;

    let data: CreateNoteRequest = serde_json::from_slice(&decrypted)
        .map_err(|e| AppError::Internal(format!("Failed to deserialize note: {}", e)))?;

    Ok(NoteResponse {
        id: NoteId(note.id),
        title: data.title,
        content: data.content,
        created_at: note.created_at,
        updated_at: note.updated_at,
    })
}

fn build_note_response(note: Note, request: CreateNoteRequest) -> AppResult<NoteResponse> {
    Ok(NoteResponse {
        id: NoteId(note.id),
        title: request.title,
        content: request.content,
        created_at: note.created_at,
        updated_at: note.updated_at,
    })
}
