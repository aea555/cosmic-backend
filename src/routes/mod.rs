//! API routes configuration.
//!
//! This module defines the complete API route structure including
//! authentication middleware and rate limiting for all endpoints.

use crate::handlers::{auth as auth_handlers, secrets as secrets_handlers};
use crate::middleware;
use crate::state::AppState;
use axum::{
    Router,
    middleware::from_fn_with_state,
    routing::{delete, get, post, put},
};
use deadpool_redis::Pool as RedisPool;

/// Builds the complete API router.
///
/// Params: AppState.
/// Logic: Creates nested routes for /auth and /secrets with appropriate middleware.
/// Returns: Configured Router.
pub fn api_routes(state: AppState) -> Router<AppState> {
    Router::new()
        .nest("/auth", auth_routes(state.cache.clone()))
        .nest("/secrets", secrets_routes(state.clone()))
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
        // Order matters: JWT first (to get user_id), then user rate limit
        .layer(from_fn_with_state(
            state.cache.clone(),
            middleware::user_rate_limit,
        ))
        .layer(from_fn_with_state(state, middleware::jwt_auth))
}
