//! Authentication business logic.
//!
//! This module contains the core authentication flows: registration, login,
//! token generation, and token validation. All cryptographic operations are
//! performed in blocking tasks to avoid blocking the async runtime.

use crate::cache;
use crate::config::Settings;
use crate::core::crypto;
use crate::error::{AppError, AppResult};
use crate::repository;
use crate::types::{AuthResponse, Claims, EncryptedBlob, MasterKey, UserId};
use chrono::{Duration, Utc};
use deadpool_redis::Pool as RedisPool;
use jsonwebtoken::{DecodingKey, EncodingKey, Header, Validation, decode, encode};
use secrecy::ExposeSecret;
use sqlx::PgPool;
use uuid::Uuid;

/// Registers a new user with email verification.
///
/// Params: Database pool, email, password, app settings.
/// Logic: Creates user with encrypted canary, generates verification token.
/// Returns: User ID and verification token (to be sent via email).
///
/// # Errors
/// Returns error if email exists or cryptographic operation fails.
pub async fn register_user(
    pool: &PgPool,
    email: &str,
    password: &str,
    _settings: &Settings,
) -> AppResult<(UserId, String)> {
    // Check if user already exists
    if repository::user::exists_by_email(pool, email).await? {
        return Err(AppError::UserAlreadyExists);
    }

    // Generate salt and derive master key in blocking task
    let password_clone = password.to_string();
    let (salt, encrypted_canary) = tokio::task::spawn_blocking(move || {
        let salt = crypto::generate_salt();
        let key = crypto::derive_master_key(&password_clone, &salt)?;
        let canary = crypto::create_canary(&key)?;
        Ok::<_, AppError>((salt, canary))
    })
    .await
    .map_err(|e| AppError::Internal(format!("Blocking task failed: {}", e)))??;

    // Create user in database
    let user =
        repository::user::create(pool, email, salt.as_bytes(), encrypted_canary.as_bytes()).await?;

    // Generate email verification token
    let verification_token = crypto::generate_verification_token();
    let token_hash = crypto::hash_verification_token(&verification_token);
    let expires_at = Utc::now() + Duration::hours(24);

    repository::verification::create(pool, user.id, &token_hash, expires_at).await?;

    Ok((UserId(user.id), verification_token))
}

/// Verifies a user's email using the verification token.
///
/// Params: Database pool, verification token.
/// Logic: Validates token, marks email as verified, deletes token.
/// Returns: Unit on success.
///
/// # Errors
/// Returns error if token is invalid or expired.
pub async fn verify_email(pool: &PgPool, token: &str) -> AppResult<()> {
    let token_hash = crypto::hash_verification_token(token);
    let verification = repository::verification::find_by_hash(pool, &token_hash).await?;

    // Check if token is expired
    if verification.expires_at < Utc::now() {
        repository::verification::delete(pool, verification.id).await?;
        return Err(AppError::InvalidVerificationToken);
    }

    // Mark email as verified
    repository::user::mark_email_verified(pool, verification.user_id).await?;

    // Delete all verification tokens for this user
    repository::verification::delete_all_for_user(pool, verification.user_id).await?;

    Ok(())
}

/// Authenticates a user and generates tokens.
///
/// Params: Database pool, cache pool, email, password, app settings.
/// Logic: Verifies canary (cache-first), generates JWT and refresh token.
/// Returns: AuthResponse with access and refresh tokens.
///
/// # Errors
/// Returns error if credentials are invalid or email not verified.
pub async fn login(
    pool: &PgPool,
    cache: &RedisPool,
    email: &str,
    password: &str,
    settings: &Settings,
) -> AppResult<AuthResponse> {
    let user = repository::user::find_by_email(pool, email).await?;

    // Check if email is verified
    if !user.email_verified {
        return Err(AppError::EmailNotVerified);
    }

    // Try to get canary from cache first
    let encrypted_canary = match cache::get_canary(cache, user.id).await {
        Ok(Some(cached)) => {
            tracing::debug!("Cache hit for user canary: {}", user.id);
            cached
        }
        _ => {
            tracing::debug!("Cache miss for user canary: {}", user.id);
            // Set canary in cache for next time
            let _ = cache::set_canary(cache, user.id, &user.encrypted_canary).await;
            user.encrypted_canary.clone()
        }
    };

    // Verify canary in blocking task
    let salt = user.salt.clone();
    let password_clone = password.to_string();

    let is_valid = tokio::task::spawn_blocking(move || {
        let salt = crate::types::Salt::try_from(salt)
            .map_err(|e| AppError::Internal(format!("Invalid salt: {}", e)))?;
        let key = crypto::derive_master_key(&password_clone, &salt)?;
        let canary = EncryptedBlob::new(encrypted_canary);
        Ok::<_, AppError>(crypto::verify_canary(&canary, &key))
    })
    .await
    .map_err(|e| AppError::Internal(format!("Blocking task failed: {}", e)))??;

    if !is_valid {
        return Err(AppError::InvalidCredentials);
    }

    // Generate tokens
    let access_token = generate_access_token(user.id, settings)?;
    let refresh_token = crypto::generate_refresh_token();
    let refresh_token_hash = crypto::hash_refresh_token(&refresh_token);
    let expires_at = Utc::now() + Duration::days(settings.refresh_token_expiry_days);

    repository::token::create(pool, user.id, &refresh_token_hash, expires_at).await?;

    Ok(AuthResponse {
        access_token,
        refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: settings.jwt_expiry_seconds,
    })
}

/// Rotates a refresh token, issuing new access and refresh tokens.
///
/// Params: Database pool, cache pool, refresh token, app settings.
/// Logic: Validates token, checks blacklist, checks for reuse, rotates token.
/// Returns: New AuthResponse with fresh tokens.
///
/// # Errors
/// Returns error if token is invalid, expired, blacklisted, or reused.
pub async fn refresh_tokens(
    pool: &PgPool,
    cache: &RedisPool,
    refresh_token: &str,
    settings: &Settings,
) -> AppResult<AuthResponse> {
    let token_hash = crypto::hash_refresh_token(refresh_token);

    // Security Check 0: Check if token is blacklisted in cache
    if cache::is_token_blacklisted(cache, &token_hash)
        .await
        .unwrap_or(false)
    {
        tracing::warn!("Attempted use of blacklisted refresh token");
        return Err(AppError::InvalidToken);
    }

    let stored_token = repository::token::find_by_hash(pool, &token_hash).await?;

    // Security Check 1: Token reuse detection
    if stored_token.used {
        tracing::warn!(
            "Refresh token reuse detected for user {}. Revoking all tokens.",
            stored_token.user_id
        );
        repository::token::revoke_all_for_user(pool, stored_token.user_id).await?;
        return Err(AppError::TokenReused);
    }

    // Security Check 2: Token expiry
    if stored_token.expires_at < Utc::now() {
        repository::token::delete(pool, stored_token.id).await?;
        return Err(AppError::TokenExpired);
    }

    // Mark current token as used
    repository::token::mark_used(pool, stored_token.id).await?;

    // Blacklist the old token in cache
    let _ = cache::blacklist_token(cache, &token_hash).await;

    // Generate new tokens
    let access_token = generate_access_token(stored_token.user_id, settings)?;
    let new_refresh_token = crypto::generate_refresh_token();
    let new_token_hash = crypto::hash_refresh_token(&new_refresh_token);
    let expires_at = Utc::now() + Duration::days(settings.refresh_token_expiry_days);

    repository::token::create(pool, stored_token.user_id, &new_token_hash, expires_at).await?;

    Ok(AuthResponse {
        access_token,
        refresh_token: new_refresh_token,
        token_type: "Bearer".to_string(),
        expires_in: settings.jwt_expiry_seconds,
    })
}

/// Logs out a user by revoking their refresh token and blacklisting it.
///
/// Params: Database pool, cache pool, refresh token.
/// Logic: Marks token as used, adds to blacklist.
/// Returns: Unit on success.
pub async fn logout(pool: &PgPool, cache: &RedisPool, refresh_token: &str) -> AppResult<()> {
    let token_hash = crypto::hash_refresh_token(refresh_token);

    // Mark in database
    if let Ok(stored_token) = repository::token::find_by_hash(pool, &token_hash).await {
        repository::token::mark_used(pool, stored_token.id).await?;
    }

    // Blacklist in cache for fast lookup
    let _ = cache::blacklist_token(cache, &token_hash).await;

    Ok(())
}

/// Generates a JWT access token.
///
/// Params: User UUID, app settings.
/// Logic: Creates signed JWT with claims.
/// Returns: Encoded JWT string.
fn generate_access_token(user_id: Uuid, settings: &Settings) -> AppResult<String> {
    let now = Utc::now();
    let exp = now + Duration::seconds(settings.jwt_expiry_seconds);

    let claims = Claims {
        sub: user_id.to_string(),
        user_id,
        exp: exp.timestamp() as usize,
        iat: now.timestamp() as usize,
    };

    encode(
        &Header::default(),
        &claims,
        &EncodingKey::from_secret(settings.jwt_secret.expose_secret().as_bytes()),
    )
    .map_err(|e| AppError::Internal(format!("Failed to generate JWT: {}", e)))
}

/// Validates a JWT access token and extracts the user ID.
///
/// Params: Token string, app settings.
/// Logic: Verifies signature and expiration.
/// Returns: UserId from the token claims.
///
/// # Errors
/// Returns InvalidToken if token is invalid or expired.
pub fn validate_access_token(token: &str, settings: &Settings) -> AppResult<UserId> {
    let token_data = decode::<Claims>(
        token,
        &DecodingKey::from_secret(settings.jwt_secret.expose_secret().as_bytes()),
        &Validation::default(),
    )
    .map_err(|_| AppError::InvalidToken)?;

    Ok(UserId(token_data.claims.user_id))
}

/// Derives the Master Key from password for a given user.
///
/// Params: Database pool, cache pool, user ID, password.
/// Logic: Fetches user salt, derives key, verifies canary (cache-first).
/// Returns: MasterKey on success.
///
/// # Errors
/// Returns error if user not found or password is incorrect.
pub async fn derive_and_verify_key(
    pool: &PgPool,
    cache: &RedisPool,
    user_id: Uuid,
    password: &str,
) -> AppResult<MasterKey> {
    let user = repository::user::find_by_id(pool, user_id).await?;

    // Try cache first for encrypted canary
    let encrypted_canary = match cache::get_canary(cache, user_id).await {
        Ok(Some(cached)) => cached,
        _ => {
            // Cache miss - get from user and populate cache
            let _ = cache::set_canary(cache, user_id, &user.encrypted_canary).await;
            user.encrypted_canary.clone()
        }
    };

    let salt = user.salt.clone();
    let password_clone = password.to_string();

    tokio::task::spawn_blocking(move || {
        let salt = crate::types::Salt::try_from(salt)
            .map_err(|e| AppError::Internal(format!("Invalid salt: {}", e)))?;
        let key = crypto::derive_master_key(&password_clone, &salt)?;
        let canary = EncryptedBlob::new(encrypted_canary);

        if !crypto::verify_canary(&canary, &key) {
            return Err(AppError::InvalidCredentials);
        }

        Ok(key)
    })
    .await
    .map_err(|e| AppError::Internal(format!("Blocking task failed: {}", e)))?
}
