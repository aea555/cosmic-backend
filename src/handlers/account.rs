//! Account management HTTP handlers.
//!
//! This module contains handlers for account-level operations:
//! - Account deletion (with OTP confirmation)
//! - Password change (with OTP and re-encryption)
//! - Email change (with OTP to new email)

use crate::cache;
use crate::core::{auth, crypto};
use crate::error::{AppError, AppJson, AppResult};
use crate::handlers::email as email_handler;
use crate::repository;
use crate::state::AppState;
use crate::types::{
    ApiResponse, ChangeEmailRequest, ChangePasswordRequest, ConfirmChangeEmailRequest,
    ConfirmChangePasswordRequest, ConfirmDeleteAccountRequest, DeleteAccountRequest,
    EmptyResponseWrapper, UserId,
};
use axum::{Extension, Json, extract::State, http::HeaderMap};
use chrono::{Duration, Utc};
use validator::Validate;

/// OTP expiry time in minutes.
const OTP_EXPIRY_MINUTES: i64 = 15;

/// Extracts the Master Password from request headers.
fn extract_master_password(headers: &HeaderMap) -> AppResult<String> {
    headers
        .get("X-Master-Password")
        .and_then(|v| v.to_str().ok())
        .map(String::from)
        .ok_or(AppError::MasterPasswordRequired)
}

/// Generates a 6-digit OTP.
fn generate_otp() -> String {
    use rand::Rng;
    let mut rng = rand::thread_rng();
    format!("{:06}", rng.gen_range(0..1000000))
}

// ----------------------------------------------------------------------------
// DELETE ACCOUNT
// ----------------------------------------------------------------------------

/// Initiates account deletion by sending OTP to user's email.
///
/// POST /api/v1/account/delete-request
#[utoipa::path(
    post,
    path = "/api/v1/account/delete-request",
    request_body = DeleteAccountRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "OTP sent", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "account"
)]
pub async fn request_delete_account(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<DeleteAccountRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Verify refresh token
    auth::validate_refresh_token(&state.db, &state.cache, &request.refresh_token).await?;

    // Get user for email
    let user = repository::user::find_by_id(&state.db, user_id.0).await?;

    // Generate and store OTP
    let otp = generate_otp();
    let otp_hash = crypto::hash_verification_token(&otp);
    let expires_at = Utc::now() + Duration::minutes(OTP_EXPIRY_MINUTES);

    repository::otp::create(
        &state.db,
        user_id.0,
        &otp_hash,
        "delete_account",
        None,
        expires_at,
    )
    .await?;

    // Send OTP email
    if let Err(e) =
        email_handler::send_otp_email(&state.config, &user.email, &otp, "delete your account").await
    {
        tracing::error!("Failed to send OTP email: {}", e);
        return Err(AppError::Internal("Failed to send OTP email".to_string()));
    }

    tracing::info!("Account deletion OTP sent for user {}", user_id.0);

    Ok(Json(ApiResponse {
        success: true,
        message: Some("OTP sent to your email. Please confirm within 15 minutes.".to_string()),
        data: None,
    }))
}

/// Confirms account deletion with OTP and deletes the account.
///
/// DELETE /api/v1/account
#[utoipa::path(
    delete,
    path = "/api/v1/account",
    request_body = ConfirmDeleteAccountRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "Account deleted", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized or Invalid OTP", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "account"
)]
pub async fn confirm_delete_account(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<ConfirmDeleteAccountRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Verify refresh token
    auth::validate_refresh_token(&state.db, &state.cache, &request.refresh_token).await?;

    // Verify OTP
    let otp_request = repository::otp::find_valid(&state.db, user_id.0, "delete_account")
        .await?
        .ok_or(AppError::InvalidOtp)?;

    let provided_hash = crypto::hash_verification_token(&request.otp);
    if provided_hash != otp_request.otp_hash {
        return Err(AppError::InvalidOtp);
    }

    // Delete user (cascades to secrets, notes, tokens)
    repository::user::delete(&state.db, user_id.0).await?;

    // Invalidate all caches for user
    let _ = cache::invalidate_secrets(&state.cache, user_id.0).await;
    let _ = cache::invalidate_notes(&state.cache, user_id.0).await;
    let _ = cache::invalidate_canary(&state.cache, user_id.0).await;

    tracing::info!("Account deleted for user {}", user_id.0);

    Ok(Json(ApiResponse {
        success: true,
        message: Some("Account deleted successfully.".to_string()),
        data: None,
    }))
}

// ----------------------------------------------------------------------------
// CHANGE PASSWORD
// ----------------------------------------------------------------------------

/// Initiates password change by sending OTP to user's email.
///
/// POST /api/v1/account/change-password-request
#[utoipa::path(
    post,
    path = "/api/v1/account/change-password-request",
    request_body = ChangePasswordRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "OTP sent", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "account"
)]
pub async fn request_change_password(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<ChangePasswordRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Verify refresh token
    auth::validate_refresh_token(&state.db, &state.cache, &request.refresh_token).await?;

    // Get user for email
    let user = repository::user::find_by_id(&state.db, user_id.0).await?;

    // Generate and store OTP
    let otp = generate_otp();
    let otp_hash = crypto::hash_verification_token(&otp);
    let expires_at = Utc::now() + Duration::minutes(OTP_EXPIRY_MINUTES);

    repository::otp::create(
        &state.db,
        user_id.0,
        &otp_hash,
        "change_password",
        None,
        expires_at,
    )
    .await?;

    // Send OTP email
    if let Err(e) =
        email_handler::send_otp_email(&state.config, &user.email, &otp, "change your password")
            .await
    {
        tracing::error!("Failed to send OTP email: {}", e);
        return Err(AppError::Internal("Failed to send OTP email".to_string()));
    }

    tracing::info!("Password change OTP sent for user {}", user_id.0);

    Ok(Json(ApiResponse {
        success: true,
        message: Some("OTP sent to your email. Please confirm within 15 minutes.".to_string()),
        data: None,
    }))
}

/// Confirms password change with OTP and re-encrypts all data.
///
/// PUT /api/v1/account/change-password
#[utoipa::path(
    put,
    path = "/api/v1/account/change-password",
    request_body = ConfirmChangePasswordRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "Password changed and data re-encrypted", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized or Invalid OTP", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "account"
)]
pub async fn confirm_change_password(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<ConfirmChangePasswordRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify current Master Password
    let old_key = auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Verify refresh token
    auth::validate_refresh_token(&state.db, &state.cache, &request.refresh_token).await?;

    // Verify OTP
    let otp_request = repository::otp::find_valid(&state.db, user_id.0, "change_password")
        .await?
        .ok_or(AppError::InvalidOtp)?;

    let provided_hash = crypto::hash_verification_token(&request.otp);
    if provided_hash != otp_request.otp_hash {
        return Err(AppError::InvalidOtp);
    }

    // Get user for salt (unused but keeping for clarity)
    let _user = repository::user::find_by_id(&state.db, user_id.0).await?;

    // Generate new salt and derive new key
    let new_salt = crypto::generate_salt();
    let new_key = crypto::derive_master_key(&request.new_password, &new_salt)?;

    // Create new canary
    let canary_payload = serde_json::json!({"msg": "OK"});
    let canary_bytes = serde_json::to_vec(&canary_payload)
        .map_err(|e| AppError::Internal(format!("Failed to serialize canary: {}", e)))?;
    let new_canary = crypto::encrypt(&canary_bytes, &new_key)?;

    // Begin transaction for re-encryption
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to begin transaction: {}", e)))?;

    // Fetch all secrets
    let secrets: Vec<crate::types::Secret> = sqlx::query_as(
        "SELECT id, user_id, encrypted_data, is_favorite, created_at, updated_at 
         FROM secrets WHERE user_id = $1",
    )
    .bind(user_id.0)
    .fetch_all(&mut *tx)
    .await?;

    // Re-encrypt secrets
    for secret in &secrets {
        let encrypted_blob = crate::types::EncryptedBlob::new(secret.encrypted_data.clone());
        let decrypted = crypto::decrypt(&encrypted_blob, &old_key)?;
        let re_encrypted = crypto::encrypt(&decrypted, &new_key)?;

        sqlx::query("UPDATE secrets SET encrypted_data = $1, updated_at = NOW() WHERE id = $2")
            .bind(re_encrypted.as_bytes())
            .bind(secret.id)
            .execute(&mut *tx)
            .await?;
    }

    // Fetch all notes
    let notes: Vec<crate::types::Note> = sqlx::query_as(
        "SELECT id, user_id, encrypted_data, is_favorite, created_at, updated_at 
         FROM notes WHERE user_id = $1",
    )
    .bind(user_id.0)
    .fetch_all(&mut *tx)
    .await?;

    // Re-encrypt notes
    for note in &notes {
        let encrypted_blob = crate::types::EncryptedBlob::new(note.encrypted_data.clone());
        let decrypted = crypto::decrypt(&encrypted_blob, &old_key)?;
        let re_encrypted = crypto::encrypt(&decrypted, &new_key)?;

        sqlx::query("UPDATE notes SET encrypted_data = $1, updated_at = NOW() WHERE id = $2")
            .bind(re_encrypted.as_bytes())
            .bind(note.id)
            .execute(&mut *tx)
            .await?;
    }

    // Update user with new salt and canary
    sqlx::query(
        "UPDATE users SET salt = $1, encrypted_canary = $2, token_version = token_version + 1, updated_at = NOW() WHERE id = $3",
    )
    .bind(new_salt.as_bytes())
    .bind(new_canary.as_bytes())
    .bind(user_id.0)
    .execute(&mut *tx)
    .await?;

    // Delete ALL OTP requests for user (invalidate all pending OTPs after successful operation)
    repository::otp::delete_all_for_user(&state.db, user_id.0).await?;

    // Revoke all refresh tokens (force re-login)
    sqlx::query("DELETE FROM refresh_tokens WHERE user_id = $1")
        .bind(user_id.0)
        .execute(&mut *tx)
        .await?;

    // Commit transaction
    tx.commit()
        .await
        .map_err(|e| AppError::Internal(format!("Failed to commit transaction: {}", e)))?;

    // Invalidate all caches
    let _ = cache::invalidate_secrets(&state.cache, user_id.0).await;
    let _ = cache::invalidate_notes(&state.cache, user_id.0).await;
    let _ = cache::invalidate_canary(&state.cache, user_id.0).await;

    tracing::info!(
        "Password changed for user {} - re-encrypted {} secrets and {} notes",
        user_id.0,
        secrets.len(),
        notes.len()
    );

    Ok(Json(ApiResponse {
        success: true,
        message: Some(format!(
            "Password changed successfully. Re-encrypted {} secrets and {} notes.",
            secrets.len(),
            notes.len()
        )),
        data: None,
    }))
}

// ----------------------------------------------------------------------------
// CHANGE EMAIL
// ----------------------------------------------------------------------------

/// Initiates email change by sending OTP to new email.
///
/// POST /api/v1/account/change-email-request
#[utoipa::path(
    post,
    path = "/api/v1/account/change-email-request",
    request_body = ChangeEmailRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "OTP sent to new email", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized", body = EmptyResponseWrapper),
        (status = 409, description = "Email already in use", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "account"
)]
pub async fn request_change_email(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<ChangeEmailRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Verify refresh token
    auth::validate_refresh_token(&state.db, &state.cache, &request.refresh_token).await?;

    // Check if new email is already in use
    if repository::user::find_by_email(&state.db, &request.new_email)
        .await
        .is_ok()
    {
        return Err(AppError::UserAlreadyExists);
    }

    // Generate and store OTP with new email
    let otp = generate_otp();
    let otp_hash = crypto::hash_verification_token(&otp);
    let expires_at = Utc::now() + Duration::minutes(OTP_EXPIRY_MINUTES);

    repository::otp::create(
        &state.db,
        user_id.0,
        &otp_hash,
        "change_email",
        Some(&request.new_email),
        expires_at,
    )
    .await?;

    // Send OTP to NEW email
    if let Err(e) = email_handler::send_otp_email(
        &state.config,
        &request.new_email,
        &otp,
        "verify your new email",
    )
    .await
    {
        tracing::error!("Failed to send OTP email: {}", e);
        return Err(AppError::Internal("Failed to send OTP email".to_string()));
    }

    tracing::info!(
        "Email change OTP sent to {} for user {}",
        request.new_email,
        user_id.0
    );

    Ok(Json(ApiResponse {
        success: true,
        message: Some("OTP sent to your new email. Please confirm within 15 minutes.".to_string()),
        data: None,
    }))
}

/// Confirms email change with OTP.
///
/// PUT /api/v1/account/change-email
#[utoipa::path(
    put,
    path = "/api/v1/account/change-email",
    request_body = ConfirmChangeEmailRequest,
    params(
        ("X-Master-Password" = String, Header, description = "Master Password")
    ),
    responses(
        (status = 200, description = "Email changed", body = EmptyResponseWrapper),
        (status = 400, description = "Validation error", body = EmptyResponseWrapper),
        (status = 401, description = "Unauthorized or Invalid OTP", body = EmptyResponseWrapper)
    ),
    security(
        ("bearer_auth" = []),
        ("master_password_auth" = [])
    ),
    tag = "account"
)]
pub async fn confirm_change_email(
    State(state): State<AppState>,
    Extension(user_id): Extension<UserId>,
    headers: HeaderMap,
    AppJson(request): AppJson<ConfirmChangeEmailRequest>,
) -> AppResult<Json<ApiResponse<()>>> {
    request
        .validate()
        .map_err(|e| AppError::Validation(e.to_string()))?;

    let master_password = extract_master_password(&headers)?;

    // Verify Master Password
    auth::verify_master_password(
        &state.db,
        &state.cache,
        user_id.0,
        &master_password,
        &state.config,
    )
    .await?;

    // Verify refresh token
    auth::validate_refresh_token(&state.db, &state.cache, &request.refresh_token).await?;

    // Verify OTP and get new email
    let otp_request = repository::otp::find_valid(&state.db, user_id.0, "change_email")
        .await?
        .ok_or(AppError::InvalidOtp)?;

    let provided_hash = crypto::hash_verification_token(&request.otp);
    if provided_hash != otp_request.otp_hash {
        return Err(AppError::InvalidOtp);
    }

    let new_email = otp_request
        .new_email
        .ok_or_else(|| AppError::Internal("New email not found in OTP request".to_string()))?;

    // Update user email
    // Update user email
    sqlx::query("UPDATE users SET email = $1, token_version = token_version + 1, updated_at = NOW() WHERE id = $2")
        .bind(&new_email)
        .bind(user_id.0)
        .execute(&state.db)
        .await?;

    // Delete ALL OTP requests for user (invalidate all pending OTPs after successful operation)
    repository::otp::delete_all_for_user(&state.db, user_id.0).await?;

    // Revoke all refresh tokens (force re-login)
    repository::token::revoke_all_for_user(&state.db, user_id.0).await?;

    tracing::info!("Email changed to {} for user {}", new_email, user_id.0);

    Ok(Json(ApiResponse {
        success: true,
        message: Some(format!("Email changed to {} successfully.", new_email)),
        data: None,
    }))
}
