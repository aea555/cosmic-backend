//! API routes configuration.
//!
//! This module defines the complete API route structure including
//! authentication middleware and rate limiting for all endpoints.

use crate::handlers::{
    account as account_handlers, auth as auth_handlers, items as items_handlers,
    secrets as secrets_handlers,
};
use crate::middleware;
use crate::state::AppState;
use axum::response::IntoResponse;
use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{delete, get, post, put},
};
use deadpool_redis::Pool as RedisPool;

/// Builds the complete API router.
///
/// Params: AppState.
/// Logic: Creates nested routes for /auth, /secrets, /notes, /items, /account with appropriate middleware.
/// Returns: Configured Router.
pub fn api_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/health", get(health_check))
        .nest("/auth", auth_routes(state.cache.clone()))
        .nest("/secrets", secrets_routes(state.clone()))
        .nest("/notes", notes_routes(state.clone()))
        .nest("/items", items_routes(state.clone()))
        .nest("/account", account_routes(state.clone()))
}

/// Simple health check handler.
async fn health_check() -> impl IntoResponse {
    axum::http::StatusCode::OK
}

/// Builds authentication routes (public, with rate limiting).
///
/// Params: Redis pool for rate limiting.
/// Logic: Routes for registration, login, token management with tiered rate limits.
/// Returns: Auth router.
fn auth_routes(cache: RedisPool) -> Router<AppState> {
    // Strict rate limiting for login and register (5/min)
    let strict_routes = Router::new()
        .route("/register", post(auth_handlers::register))
        .route("/login", post(auth_handlers::login))
        .layer(from_fn_with_state(
            cache.clone(),
            middleware::auth_strict_rate_limit,
        ));

    // Medium rate limiting for other auth endpoints (10/min)
    let medium_routes = Router::new()
        .route("/verify-email", post(auth_handlers::verify_email))
        .route("/verify-redirect", get(auth_handlers::verify_redirect))
        .route(
            "/resend-verification",
            post(auth_handlers::resend_verification),
        )
        .route("/refresh", post(auth_handlers::refresh))
        .route("/logout", post(auth_handlers::logout))
        .layer(from_fn_with_state(
            cache,
            middleware::auth_medium_rate_limit,
        ));

    Router::new().merge(strict_routes).merge(medium_routes)
}

/// Builds secrets routes (protected by JWT middleware with user rate limiting).
///
/// Params: AppState for middleware.
/// Logic: CRUD routes for secrets with JWT auth + per-user rate limiting.
/// Returns: Secrets router.
fn secrets_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/", get(secrets_handlers::list_secrets))
        .route("/", post(secrets_handlers::create_secret))
        .route("/{id}", get(secrets_handlers::get_secret))
        .route("/{id}", put(secrets_handlers::update_secret))
        .route("/{id}", delete(secrets_handlers::delete_secret))
        .route("/{id}/favorite", put(secrets_handlers::favorite_secret))
        .route("/{id}/unfavorite", put(secrets_handlers::unfavorite_secret))
        // Order matters: JWT first (to get user_id), then user rate limit
        .layer(from_fn_with_state(
            state.cache.clone(),
            middleware::user_rate_limit,
        ))
        .layer(from_fn_with_state(state, middleware::jwt_auth))
}

/// Builds notes routes (protected by JWT middleware with user rate limiting).
///
/// Params: AppState for middleware.
/// Logic: CRUD routes for notes with JWT auth + per-user rate limiting.
/// Returns: Notes router.
fn notes_routes(state: AppState) -> Router<AppState> {
    use crate::handlers::notes as notes_handlers;

    Router::new()
        .route("/", get(notes_handlers::list_notes))
        .route("/", post(notes_handlers::create_note))
        .route("/{id}", get(notes_handlers::get_note))
        .route("/{id}", put(notes_handlers::update_note))
        .route("/{id}", delete(notes_handlers::delete_note))
        .route("/{id}/favorite", put(notes_handlers::favorite_note))
        .route("/{id}/unfavorite", put(notes_handlers::unfavorite_note))
        // Order matters: JWT first (to get user_id), then user rate limit
        .layer(from_fn_with_state(
            state.cache.clone(),
            middleware::user_rate_limit,
        ))
        .layer(from_fn_with_state(state, middleware::jwt_auth))
}

/// Builds items routes for bulk operations (protected by JWT middleware).
///
/// Params: AppState for middleware.
/// Logic: Bulk create/delete/favorite operations with JWT auth + per-user rate limiting.
/// Returns: Items router.
fn items_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .route("/bulk-create", post(items_handlers::bulk_create))
        .route("/bulk-delete", delete(items_handlers::bulk_delete))
        .route("/bulk-favorite", put(items_handlers::bulk_favorite))
        .route("/bulk-unfavorite", put(items_handlers::bulk_unfavorite))
        .layer(from_fn_with_state(
            state.cache.clone(),
            middleware::user_rate_limit,
        ))
        .layer(from_fn_with_state(state, middleware::jwt_auth))
}

/// Builds account routes for account management (protected by JWT middleware).
///
/// Params: AppState for middleware.
/// Logic: Account deletion, password change, email change with JWT auth + per-user rate limiting.
/// Returns: Account router.
fn account_routes(state: AppState) -> Router<AppState> {
    Router::new()
        // Delete account (request OTP + confirm with OTP)
        .route(
            "/delete-request",
            post(account_handlers::request_delete_account),
        )
        .route("/", delete(account_handlers::confirm_delete_account))
        // Change password (request OTP + confirm with OTP + re-encrypt)
        /* DISABLED due to re-encryption issues
        .route(
            "/change-password-request",
            post(account_handlers::request_change_password),
        )
        .route(
            "/change-password",
            put(account_handlers::confirm_change_password),
        )
        */
        // Change email (request OTP to new email + confirm with OTP)
        .route(
            "/change-email-request",
            post(account_handlers::request_change_email),
        )
        .route("/change-email", put(account_handlers::confirm_change_email))
        .layer(from_fn_with_state(
            state.cache.clone(),
            middleware::user_rate_limit,
        ))
        .layer(from_fn_with_state(state, middleware::jwt_auth))
}
