//! Secrets HTTP handlers.
//!
//! This module contains the HTTP handlers for secret management endpoints.
//! All endpoints require JWT authentication and X-Master-Password header.

use crate::cache;
use crate::core::{auth, vault};
use crate::error::{AppError, AppJson, AppResult};
use crate::state::AppState;
use crate::types::{
    ApiResponse, CreateSecretRequest, EmptyResponseWrapper, SecretListResponseWrapper,
    SecretResponse, SecretResponseWrapper, UpdateSecretRequest, UserId,
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

/// Lists all decrypted secrets for the authenticated user.
///
/// Params: AppState, user ID from JWT, request headers.
/// Logic: Verifies Master Password, decrypts all secrets (uses cache).
/// Returns: Array of decrypted secrets.
///
/// GET /api/v1/secrets
#[utoipa::path(
    get,
    path = "/api/v1/secrets",
    params(
        ("X-Master-Password" = String, Header, description = "Master Password for decryption")
    ),
    responses(
        (status = 200, description = "List of secrets", body = SecretListResponseWrapper),
        (status = 401, description = "Unauthorized or Invalid Master Password", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "secrets"
)]
pub async fn list_secrets(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<Vec<SecretResponse>>>> {
    let password = extract_master_password(&headers)?;

    // Verify Master Password and get key (uses cache for canary)
    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    // Get all decrypted secrets
    let secrets = vault::get_all_secrets(&state.db, user_id.into_inner(), key).await?;

    Ok(Json(ApiResponse::success(secrets)))
}

/// Gets a single decrypted secret.
///
/// Params: AppState, secret ID path param, user ID from JWT, request headers.
/// Logic: Verifies ownership and Master Password, decrypts secret.
/// Returns: Decrypted secret.
///
/// GET /api/v1/secrets/:id
#[utoipa::path(
    get,
    path = "/api/v1/secrets/{id}",
    params(
        ("id" = Uuid, Path, description = "Secret ID"),
        ("X-Master-Password" = String, Header, description = "Master Password for decryption")
    ),
    responses(
        (status = 200, description = "Secret details", body = SecretResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 404, description = "Secret not found", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "secrets"
)]
pub async fn get_secret(
    State(state): State<AppState>,
    Path(secret_id): Path<Uuid>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<SecretResponse>>> {
    let password = extract_master_password(&headers)?;

    // Verify Master Password and get key
    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    // Get and decrypt secret
    let secret = vault::get_secret(&state.db, secret_id, user_id.into_inner(), &key).await?;

    Ok(Json(ApiResponse::success(secret)))
}

/// Creates a new encrypted secret.
///
/// Params: AppState, user ID from JWT, request headers, secret data body.
/// Logic: Validates input, verifies Master Password, encrypts and stores.
///        Invalidates secrets cache after write.
/// Returns: 201 Created with the new secret.
///
/// POST /api/v1/secrets
#[utoipa::path(
    post,
    path = "/api/v1/secrets",
    request_body = CreateSecretRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password for encryption")
    ),
    responses(
        (status = 201, description = "Secret created", body = SecretResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "secrets"
)]
pub async fn create_secret(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<CreateSecretRequest>,
) -> AppResult<(StatusCode, Json<ApiResponse<SecretResponse>>)> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let password = extract_master_password(&headers)?;

    // Verify Master Password and get key
    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    // Create encrypted secret
    let secret = vault::create_secret(&state.db, user_id.into_inner(), request, &key).await?;

    // Invalidate secrets cache after write
    let _ = cache::invalidate_secrets(&state.cache, user_id.into_inner()).await;

    tracing::info!("Secret created: {}", secret.id);

    Ok((StatusCode::CREATED, Json(ApiResponse::success(secret))))
}

/// Updates an existing secret.
///
/// Params: AppState, secret ID path param, user ID from JWT, headers, data body.
/// Logic: Verifies ownership and Master Password, re-encrypts and updates.
///        Invalidates secrets cache after write.
/// Returns: Updated secret.
///
/// PUT /api/v1/secrets/:id
#[utoipa::path(
    put,
    path = "/api/v1/secrets/{id}",
    request_body = UpdateSecretRequest,
    params(
        ("id" = Uuid, Path, description = "Secret ID"),
        ("X-Master-Password" = String, Header, description = "Master Password for encryption")
    ),
    responses(
        (status = 200, description = "Secret updated", body = SecretResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 404, description = "Secret not found", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "secrets"
)]
pub async fn update_secret(
    State(state): State<AppState>,
    Path(secret_id): Path<Uuid>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<UpdateSecretRequest>,
) -> AppResult<Json<ApiResponse<SecretResponse>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let password = extract_master_password(&headers)?;

    // Verify Master Password and get key
    let key = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    // Update encrypted secret
    let secret =
        vault::update_secret(&state.db, secret_id, user_id.into_inner(), request, &key).await?;

    // Invalidate secrets cache after write
    let _ = cache::invalidate_secrets(&state.cache, user_id.into_inner()).await;

    tracing::info!("Secret updated: {}", secret.id);

    Ok(Json(ApiResponse::success(secret)))
}

/// Deletes a secret.
///
/// Params: AppState, secret ID path param, user ID from JWT.
/// Logic: Verifies ownership, deletes secret, invalidates cache.
/// Returns: 200 OK with confirmation message.
///
/// DELETE /api/v1/secrets/:id
#[utoipa::path(
    delete,
    path = "/api/v1/secrets/{id}",
    params(
        ("id" = Uuid, Path, description = "Secret ID"),
        ("X-Master-Password" = String, Header, description = "Master Password for verification")
    ),
    responses(
        (status = 200, description = "Secret deleted", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 404, description = "Secret not found", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "secrets"
)]
pub async fn delete_secret(
    State(state): State<AppState>,
    Path(secret_id): Path<Uuid>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
) -> AppResult<Json<ApiResponse<()>>> {
    let password = extract_master_password(&headers)?;

    // Verify Master Password (Canary Check) before allowing deletion
    // We don't need the key for deletion, but we MUST verify the user has it.
    let _ = auth::derive_and_verify_key(&state.db, &state.cache, user_id.into_inner(), &password)
        .await?;

    vault::delete_secret(&state.db, secret_id, user_id.into_inner()).await?;

    // Invalidate secrets cache after delete
    let _ = cache::invalidate_secrets(&state.cache, user_id.into_inner()).await;

    tracing::info!("Secret deleted: {}", secret_id);

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Secret deleted successfully".to_string()),
        data: None,
    }))
}
