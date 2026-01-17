//! Notes HTTP handlers.
//!
//! This module contains the HTTP handlers for note management endpoints.
//! All endpoints require JWT authentication and X-Master-Password header.

use crate::cache;
use crate::core::{auth, vault};
use crate::error::{AppError, AppJson, AppResult};
use crate::state::AppState;
use crate::types::{
    ApiResponse, CreateNoteRequest, EmptyResponseWrapper, NoteListResponseWrapper, NoteResponse,
    NoteResponseWrapper, UpdateNoteRequest, UserId,
};
use axum::{
    Extension, Json,
    extract::{Path, State},
    http::{HeaderMap, StatusCode},
};
use uuid::Uuid;
use validator::Validate;

/// Extracts the Master Password from request headers.
///
/// Params: Request headers.
/// Logic: Looks for X-Master-Password header.
/// Returns: Password string or MasterPasswordRequired error.
fn extract_master_password(headers: &HeaderMap) -> AppResult<String> {
    headers
        .get("X-Master-Password")
        .and_then(|v| v.to_str().ok())
        .map(|s| s.to_string())
        .ok_or(AppError::MasterPasswordRequired)
}

/// Lists all decrypted notes for the authenticated user.
///
/// Params: AppState, user ID from JWT, request headers.
/// Logic: Verifies Master Password, decrypts all notes.
/// Returns: Array of decrypted notes.
///
/// GET /api/v1/notes
#[utoipa::path(
    get,
    path = "/api/v1/notes",
    params(
        ("X-Master-Password" = String, Header, description = "Master Password for decryption")
    ),
    responses(
        (status = 200, description = "List of notes", body = NoteListResponseWrapper),
        (status = 401, description = "Unauthorized or Invalid Master Password", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "notes"
)]
pub async fn list_notes(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<NoteResponse>>>> {
    let password = extract_master_password(&headers)?;

    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    let notes = vault::get_all_notes(&state.db, user_id.into_inner(), key).await?;

    Ok(Json(ApiResponse::success(notes)))
}

/// Gets a single decrypted note.
///
/// Params: AppState, note ID path param, user ID from JWT, request headers.
/// Logic: Verifies ownership and Master Password, decrypts note.
/// Returns: Decrypted note.
///
/// GET /api/v1/notes/:id
#[utoipa::path(
    get,
    path = "/api/v1/notes/{id}",
    params(
        ("id" = Uuid, Path, description = "Note ID"),
        ("X-Master-Password" = String, Header, description = "Master Password for decryption")
    ),
    responses(
        (status = 200, description = "Note details", body = NoteResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 404, description = "Note not found", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "notes"
)]
pub async fn get_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<NoteResponse>>> {
    let password = extract_master_password(&headers)?;

    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    let note = vault::get_note(&state.db, note_id, user_id.into_inner(), &key).await?;

    Ok(Json(ApiResponse::success(note)))
}

/// Creates a new encrypted note.
///
/// Params: AppState, user ID from JWT, headers, data body.
/// Logic: Verifies Master Password, encrypts and stores note, invalidates cache.
/// Returns: Created note.
///
/// POST /api/v1/notes
#[utoipa::path(
    post,
    path = "/api/v1/notes",
    request_body = CreateNoteRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password for encryption")
    ),
    responses(
        (status = 201, description = "Note created", body = NoteResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "notes"
)]
pub async fn create_note(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<CreateNoteRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<NoteResponse>>)> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let password = extract_master_password(&headers)?;

    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    let note = vault::create_note(&state.db, user_id.into_inner(), request, &key).await?;

    // Invalidate notes cache after write
    let _ = cache::invalidate_notes(&state.cache, user_id.into_inner()).await;

    tracing::info!("Note created: {}", note.id);

    Ok((StatusCode::CREATED, Json(ApiResponse::success(note))))
}

/// Updates an existing note.
///
/// Params: AppState, note ID path param, user ID from JWT, headers, data body.
/// Logic: Verifies ownership and Master Password, re-encrypts and updates, invalidates cache.
/// Returns: Updated note.
///
/// PUT /api/v1/notes/:id
#[utoipa::path(
    put,
    path = "/api/v1/notes/{id}",
    request_body = UpdateNoteRequest,
    params(
        ("id" = Uuid, Path, description = "Note ID"),
        ("X-Master-Password" = String, Header, description = "Master Password for encryption")
    ),
    responses(
        (status = 200, description = "Note updated", body = NoteResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 404, description = "Note not found", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "notes"
)]
pub async fn update_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<UpdateNoteRequest>,
) -> AppResult<Json<ApiResponse<NoteResponse>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let password = extract_master_password(&headers)?;

    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    let note = vault::update_note(&state.db, note_id, user_id.into_inner(), request, &key).await?;

    // Invalidate notes cache after write
    let _ = cache::invalidate_notes(&state.cache, user_id.into_inner()).await;

    tracing::info!("Note updated: {}", note.id);

    Ok(Json(ApiResponse::success(note)))
}

/// Deletes a note.
///
/// Params: AppState, note ID path param, user ID from JWT.
/// Logic: Verifies ownership and Master Password, deletes note, invalidates cache.
/// Returns: 200 OK with confirmation message.
///
/// DELETE /api/v1/notes/:id
#[utoipa::path(
    delete,
    path = "/api/v1/notes/{id}",
    params(
        ("id" = Uuid, Path, description = "Note ID"),
        ("X-Master-Password" = String, Header, description = "Master Password for verification")
    ),
    responses(
        (status = 200, description = "Note deleted", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 404, description = "Note not found", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "notes"
)]
pub async fn delete_note(
    State(state): State<AppState>,
    Path(note_id): Path<Uuid>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<()>>> {
    let password = extract_master_password(&headers)?;

    // Verify Master Password (Canary Check) before allowing deletion
    let _ = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    vault::delete_note(&state.db, note_id, user_id.into_inner()).await?;

    // Invalidate notes cache after delete
    let _ = cache::invalidate_notes(&state.cache, user_id.into_inner()).await;

    tracing::info!("Note deleted: {}", note_id);

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Note deleted successfully".to_string()),
        data: None,
    }))
}
