//! Items HTTP handlers for bulk operations.
//!
//! This module contains the HTTP handlers for bulk item operations including
//! bulk create, bulk delete, and bulk favorite/unfavorite.
//! All endpoints require JWT authentication and X-Master-Password header.

use crate::cache;
use crate::core::auth;
use crate::error::{AppError, AppJson, AppResult};
use crate::state::AppState;
use crate::types::{
    ApiResponse, BulkCreateRequest, BulkCreateResponse, BulkCreateResponseWrapper,
    BulkCreateResultItem, BulkDeleteRequest, BulkDeleteResponse, BulkDeleteResponseWrapper,
    BulkFavoriteRequest, BulkFavoriteResponse, BulkFavoriteResponseWrapper, CreateNoteRequest,
    CreateSecretRequest, EmptyResponseWrapper, ItemType, UserId,
};
use axum::{
    Extension, Json,
    extract::State,
    http::{HeaderMap, StatusCode},
};
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
        .map(String::from)
        .ok_or(AppError::MasterPasswordRequired)
}

/// Internal enum to hold parsed requests during validation phase
enum ParsedItem {
    Secret(CreateSecretRequest),
    Note(CreateNoteRequest),
}

/// Bulk creates secrets and/or notes.
///
/// Params: AppState, user ID from JWT, request headers, bulk create request body.
/// Logic: Verifies Master Password, validates ALL items collecting errors,
///        then encrypts and stores all items in a transaction.
/// Returns: 201 Created with created item IDs.
///
/// POST /api/v1/items/bulk-create
#[utoipa::path(
    post,
    path = "/api/v1/items/bulk-create",
    request_body = BulkCreateRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password for encryption")
    ),
    responses(
        (status = 201, description = "Items created", body = BulkCreateResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "items"
)]
pub async fn bulk_create(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<BulkCreateRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<BulkCreateResponse>>)> {
    // Phase 1: Authentication
    let master_password = extract_master_password(&headers)?;

    // Verify Master Password via Canary check
    let master_key = auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Phase 2: Validation
    let mut parsed_items = Vec::with_capacity(request.items.len());
    let mut validation_errors = Vec::new();

    for (index, item) in request.items.iter().enumerate() {
        match item.item_type {
            ItemType::Secret => {
                match serde_json::from_value::<CreateSecretRequest>(item.data.clone()) {
                    Ok(data) => {
                        if let Err(e) = data.validate() {
                            validation_errors.push(format!("Item {} (Secret): {}", index, e));
                        } else {
                            parsed_items.push(ParsedItem::Secret(data));
                        }
                    }
                    Err(e) => {
                        validation_errors
                            .push(format!("Item {} (Secret): Invalid format: {}", index, e));
                    }
                }
            }
            ItemType::Note => {
                match serde_json::from_value::<CreateNoteRequest>(item.data.clone()) {
                    Ok(data) => {
                        if let Err(e) = data.validate() {
                            validation_errors.push(format!("Item {} (Note): {}", index, e));
                        } else {
                            parsed_items.push(ParsedItem::Note(data));
                        }
                    }
                    Err(e) => {
                        validation_errors
                            .push(format!("Item {} (Note): Invalid format: {}", index, e));
                    }
                }
            }
        }
    }

    if !validation_errors.is_empty() {
        return Err(AppError::Validation(validation_errors.join("; ")));
    }

    // Phase 3: Execution
    let mut created_items = Vec::with_capacity(parsed_items.len());
    let mut secrets_created = false;
    let mut notes_created = false;

    // Process each item - in a transaction for all-or-nothing
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to begin transaction: {}", e)))?;

    for item in parsed_items {
        match item {
            ParsedItem::Secret(secret_data) => {
                // Encrypt the secret
                let json_data = serde_json::to_vec(&secret_data).map_err(|e| {
                    AppError::Internal(format!("Failed to serialize secret: {}", e))
                })?;
                let encrypted = crate::core::crypto::encrypt(&json_data, &master_key)?;

                // Insert into database (using transaction)
                let secret = sqlx::query_as::<_, crate::types::Secret>(
                    "INSERT INTO secrets (user_id, encrypted_data)
                     VALUES ($1, $2)
                     RETURNING id, user_id, encrypted_data, is_favorite, created_at, updated_at",
                )
                .bind(user_id.0)
                .bind(encrypted.as_bytes())
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                created_items.push(BulkCreateResultItem {
                    id: secret.id,
                    item_type: ItemType::Secret,
                });
                secrets_created = true;
            }
            ParsedItem::Note(note_data) => {
                // Encrypt the note
                let json_data = serde_json::to_vec(&note_data)
                    .map_err(|e| AppError::Internal(format!("Failed to serialize note: {}", e)))?;
                let encrypted = crate::core::crypto::encrypt(&json_data, &master_key)?;

                // Insert into database (using transaction)
                let note = sqlx::query_as::<_, crate::types::Note>(
                    "INSERT INTO notes (user_id, encrypted_data)
                     VALUES ($1, $2)
                     RETURNING id, user_id, encrypted_data, is_favorite, created_at, updated_at",
                )
                .bind(user_id.0)
                .bind(encrypted.as_bytes())
                .fetch_one(&mut *tx)
                .await
                .map_err(AppError::Database)?;

                created_items.push(BulkCreateResultItem {
                    id: note.id,
                    item_type: ItemType::Note,
                });
                notes_created = true;
            }
        }
    }

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to commit transaction: {}", e)))?;

    // Invalidate caches
    if secrets_created {
        let _ = cache::invalidate_secrets(&state.cache, user_id.0).await;
    }
    if notes_created {
        let _ = cache::invalidate_notes(&state.cache, user_id.0).await;
    }

    let created_count = created_items.len();
    tracing::info!(
        "Bulk created {} items for user {}",
        created_count,
        user_id.0
    );

    Ok((
        StatusCode::CREATED,
        Json(ApiResponse {
            success: true,
            message: Some(format!("Created {}/{} items", created_count, created_count)),
            data: Some(BulkCreateResponse {
                created_count,
                items: created_items,
            }),
        }),
    ))
}

/// Bulk deletes secrets and/or notes.
///
/// Params: AppState, user ID from JWT, request headers, bulk delete request body.
/// Logic: Verifies Master Password, validates all items exist and belong to user,
///        deletes in a transaction. All-or-nothing semantics.
/// Returns: 200 OK with deleted count.
///
/// DELETE /api/v1/items/bulk-delete
#[utoipa::path(
    delete,
    path = "/api/v1/items/bulk-delete",
    request_body = BulkDeleteRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "Items deleted", body = BulkDeleteResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "items"
)]
pub async fn bulk_delete(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<BulkDeleteRequest>,
) -> AppResult<Json<ApiResponse<BulkDeleteResponse>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password via Canary check
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Separate items by type
    let secret_ids: Vec<uuid::Uuid> = request
        .items
        .iter()
        .filter(|i| i.item_type == ItemType::Secret)
        .map(|i| i.id)
        .collect();

    let note_ids: Vec<uuid::Uuid> = request
        .items
        .iter()
        .filter(|i| i.item_type == ItemType::Note)
        .map(|i| i.id)
        .collect();

    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to begin transaction: {}", e)))?;

    let mut deleted_count = 0;

    // Delete secrets
    if !secret_ids.is_empty() {
        // First validate all secrets exist and belong to user
        let existing: Vec<(uuid::Uuid,)> =
            sqlx::query_as("SELECT id FROM secrets WHERE id = ANY($1) AND user_id = $2")
                .bind(&secret_ids)
                .bind(user_id.0)
                .fetch_all(&mut *tx)
                .await?;

        if existing.len() != secret_ids.len() {
            return Err(AppError::Validation(
                "One or more secrets not found or not owned by user".to_string(),
            ));
        }

        // Delete
        let result = sqlx::query("DELETE FROM secrets WHERE id = ANY($1) AND user_id = $2")
            .bind(&secret_ids)
            .bind(user_id.0)
            .execute(&mut *tx)
            .await?;

        deleted_count += result.rows_affected() as usize;

        // Invalidate individual caches
        for id in &secret_ids {
            let _ = cache::invalidate_secret_by_id(&state.cache, *id).await;
        }
    }

    // Delete notes
    if !note_ids.is_empty() {
        // First validate all notes exist and belong to user
        let existing: Vec<(uuid::Uuid,)> =
            sqlx::query_as("SELECT id FROM notes WHERE id = ANY($1) AND user_id = $2")
                .bind(&note_ids)
                .bind(user_id.0)
                .fetch_all(&mut *tx)
                .await?;

        if existing.len() != note_ids.len() {
            return Err(AppError::Validation(
                "One or more notes not found or not owned by user".to_string(),
            ));
        }

        // Delete
        let result = sqlx::query("DELETE FROM notes WHERE id = ANY($1) AND user_id = $2")
            .bind(&note_ids)
            .bind(user_id.0)
            .execute(&mut *tx)
            .await?;

        deleted_count += result.rows_affected() as usize;

        // Invalidate individual caches
        for id in &note_ids {
            let _ = cache::invalidate_note_by_id(&state.cache, *id).await;
        }
    }

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to commit transaction: {}", e)))?;

    // Invalidate list caches
    if !secret_ids.is_empty() {
        let _ = cache::invalidate_secrets(&state.cache, user_id.0).await;
    }
    if !note_ids.is_empty() {
        let _ = cache::invalidate_notes(&state.cache, user_id.0).await;
    }

    tracing::info!(
        "Bulk deleted {} items for user {}",
        deleted_count,
        user_id.0
    );

    Ok(Json(ApiResponse {
        success: true,
        message: Some(format!(
            "Deleted {}/{} items",
            deleted_count,
            request.items.len()
        )),
        data: Some(BulkDeleteResponse { deleted_count }),
    }))
}

/// Bulk favorites secrets and/or notes.
///
/// Params: AppState, user ID from JWT, request headers, bulk favorite request body.
/// Logic: Verifies Master Password, updates favorite status for all items.
/// Returns: 200 OK with updated count.
///
/// PUT /api/v1/items/bulk-favorite
#[utoipa::path(
    put,
    path = "/api/v1/items/bulk-favorite",
    request_body = BulkFavoriteRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "Items favorited", body = BulkFavoriteResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "items"
)]
pub async fn bulk_favorite(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<BulkFavoriteRequest>,
) -> AppResult<Json<ApiResponse<BulkFavoriteResponse>>> {
    bulk_set_favorite(state, user_id, headers, request, true).await
}

/// Bulk unfavorites secrets and/or notes.
///
/// Params: AppState, user ID from JWT, request headers, bulk favorite request body.
/// Logic: Verifies Master Password, updates favorite status for all items.
/// Returns: 200 OK with updated count.
///
/// PUT /api/v1/items/bulk-unfavorite
#[utoipa::path(
    put,
    path = "/api/v1/items/bulk-unfavorite",
    request_body = BulkFavoriteRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "Items unfavorited", body = BulkFavoriteResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "items"
)]
pub async fn bulk_unfavorite(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<BulkFavoriteRequest>,
) -> AppResult<Json<ApiResponse<BulkFavoriteResponse>>> {
    bulk_set_favorite(state, user_id, headers, request, false).await
}

/// Internal helper to set favorite status for bulk items.
async fn bulk_set_favorite(
    state: AppState,
    user_id: UserId,
    headers: HeaderMap,
    request: BulkFavoriteRequest,
    is_favorite: bool,
) -> AppResult<Json<ApiResponse<BulkFavoriteResponse>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password via Canary check
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Separate items by type
    let secret_ids: Vec<uuid::Uuid> = request
        .items
        .iter()
        .filter(|i| i.item_type == ItemType::Secret)
        .map(|i| i.id)
        .collect();

    let note_ids: Vec<uuid::Uuid> = request
        .items
        .iter()
        .filter(|i| i.item_type == ItemType::Note)
        .map(|i| i.id)
        .collect();

    let mut updated_count = 0;

    // Update secrets
    if !secret_ids.is_empty() {
        let result = sqlx::query(
            "UPDATE secrets SET is_favorite = $1, updated_at = NOW() 
             WHERE id = ANY($2) AND user_id = $3",
        )
        .bind(is_favorite)
        .bind(&secret_ids)
        .bind(user_id.0)
        .execute(&state.db)
        .await?;

        updated_count += result.rows_affected() as usize;

        // Invalidate caches
        for id in &secret_ids {
            let _ = cache::invalidate_secret_by_id(&state.cache, *id).await;
        }
        let _ = cache::invalidate_secrets(&state.cache, user_id.0).await;
    }

    // Update notes
    if !note_ids.is_empty() {
        let result = sqlx::query(
            "UPDATE notes SET is_favorite = $1, updated_at = NOW() 
             WHERE id = ANY($2) AND user_id = $3",
        )
        .bind(is_favorite)
        .bind(&note_ids)
        .bind(user_id.0)
        .execute(&state.db)
        .await?;

        updated_count += result.rows_affected() as usize;

        // Invalidate caches
        for id in &note_ids {
            let _ = cache::invalidate_note_by_id(&state.cache, *id).await;
        }
        let _ = cache::invalidate_notes(&state.cache, user_id.0).await;
    }

    let action = if is_favorite {
        "favorited"
    } else {
        "unfavorited"
    };
    tracing::info!(
        "Bulk {} {} items for user {}",
        action,
        updated_count,
        user_id.0
    );

    Ok(Json(ApiResponse {
        success: true,
        message: Some(format!(
            "{} {}/{} items",
            if is_favorite {
                "Favorited"
            } else {
                "Unfavorited"
            },
            updated_count,
            request.items.len()
        )),
        data: Some(BulkFavoriteResponse { updated_count }),
    }))
}
