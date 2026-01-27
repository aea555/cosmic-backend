//! Note repository for database operations.
//!
//! This module handles all database queries related to encrypted notes.
//! All data stored is encrypted with the user's Master Key.

use crate::error::{AppError, AppResult};
use crate::types::Note;
use sqlx::PgPool;
use uuid::Uuid;

/// Finds all notes for a user.
///
/// Params: Database pool reference, user UUID.
/// Logic: Fetches all encrypted note records for the user.
/// Returns: Vector of Note records (still encrypted).
pub async fn find_all_by_user(pool: &PgPool, user_id: Uuid) -> AppResult<Vec<Note>> {
    let notes = sqlx::query_as::<_, Note>(
        "SELECT id, user_id, encrypted_data, is_favorite, created_at, updated_at
         FROM notes
         WHERE user_id = $1
         ORDER BY created_at DESC",
    )
    .bind(user_id)
    .fetch_all(pool)
    .await?;

    Ok(notes)
}

/// Finds a specific note by ID and user.
///
/// Params: Database pool, note UUID, user UUID.
/// Logic: Fetches single note, ensuring user ownership.
/// Returns: Note if found and owned by user, NoteNotFound (generically SecretNotFound or potentially new error) otherwise.
pub async fn find_by_id(pool: &PgPool, note_id: Uuid, user_id: Uuid) -> AppResult<Note> {
    sqlx::query_as::<_, Note>(
        "SELECT id, user_id, encrypted_data, is_favorite, created_at, updated_at
         FROM notes
         WHERE id = $1 AND user_id = $2",
    )
    .bind(note_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::SecretNotFound)
}

/// Creates a new encrypted note for a user.
///
/// Params: Database pool, user UUID, encrypted data bytes.
/// Logic: Inserts new note record with encrypted data.
/// Returns: The created Note record.
pub async fn create(pool: &PgPool, user_id: Uuid, encrypted_data: &[u8]) -> AppResult<Note> {
    sqlx::query_as::<_, Note>(
        "INSERT INTO notes (user_id, encrypted_data)
         VALUES ($1, $2)
         RETURNING id, user_id, encrypted_data, is_favorite, created_at, updated_at",
    )
    .bind(user_id)
    .bind(encrypted_data)
    .fetch_one(pool)
    .await
    .map_err(AppError::Database)
}

/// Updates an existing note's encrypted data.
///
/// Params: Database pool, note UUID, user UUID, new encrypted data.
/// Logic: Updates encrypted_data, ensuring user ownership.
/// Returns: Updated Note record, Error if not found.
pub async fn update(
    pool: &PgPool,
    note_id: Uuid,
    user_id: Uuid,
    encrypted_data: &[u8],
) -> AppResult<Note> {
    sqlx::query_as::<_, Note>(
        "UPDATE notes
         SET encrypted_data = $1, updated_at = NOW()
         WHERE id = $2 AND user_id = $3
         RETURNING id, user_id, encrypted_data, is_favorite, created_at, updated_at",
    )
    .bind(encrypted_data)
    .bind(note_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::SecretNotFound)
}

/// Deletes a note by ID and user.
///
/// Params: Database pool, note UUID, user UUID.
/// Logic: Removes note, ensuring user ownership.
/// Returns: True if deleted, false if not found.
pub async fn delete(pool: &PgPool, note_id: Uuid, user_id: Uuid) -> AppResult<bool> {
    let result = sqlx::query("DELETE FROM notes WHERE id = $1 AND user_id = $2")
        .bind(note_id)
        .bind(user_id)
        .execute(pool)
        .await?;

    Ok(result.rows_affected() > 0)
}

/// Updates the favorite status of a note.
///
/// Params: Database pool, note UUID, user UUID, is_favorite flag.
/// Logic: Updates is_favorite field, ensuring user ownership.
/// Returns: Updated Note record, Error if not found.
pub async fn update_favorite(
    pool: &PgPool,
    note_id: Uuid,
    user_id: Uuid,
    is_favorite: bool,
) -> AppResult<Note> {
    sqlx::query_as::<_, Note>(
        "UPDATE notes
         SET is_favorite = $1, updated_at = NOW()
         WHERE id = $2 AND user_id = $3
         RETURNING id, user_id, encrypted_data, is_favorite, created_at, updated_at",
    )
    .bind(is_favorite)
    .bind(note_id)
    .bind(user_id)
    .fetch_optional(pool)
    .await?
    .ok_or(AppError::SecretNotFound)
}
