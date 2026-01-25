//! Application bootstrapping and server setup.
//!
//! This module contains the application factory that initializes all infrastructure
//! components and builds the Axum router with middleware.

use crate::config::Settings;
use crate::error::AppResult;
use crate::routes;
use crate::state::AppState;
use axum::Router;
use deadpool_redis::{Config as RedisConfig, Runtime};
use secrecy::ExposeSecret;
use sqlx::postgres::PgPoolOptions;
use std::time::Duration;
use tower_http::compression::CompressionLayer;
use tower_http::cors::{Any, CorsLayer};
use tower_http::trace::TraceLayer;

/// Builds and returns the complete application.
///
/// Params: Application settings.
/// Logic: Initializes database and cache pools, runs migrations, builds router.
/// Returns: Configured Axum Router ready to serve requests.
///
/// # Errors
/// Returns error if database connection or migration fails.
pub async fn build_app(settings: Settings) -> AppResult<Router> {
    tracing::info!(
        "Initializing database connection pool (max: {}, timeout: {}s)",
        settings.database_pool_max,
        settings.database_acquire_timeout_secs
    );
    let db_pool = PgPoolOptions::new()
        .max_connections(settings.database_pool_max)
        .acquire_timeout(Duration::from_secs(settings.database_acquire_timeout_secs))
        .connect(settings.database_url.expose_secret())
        .await
        .map_err(|e| {
            tracing::error!("Failed to connect to database: {}", e);
            e
        })?;

    tracing::info!("Running database migrations");
    sqlx::migrate!("./migrations")
        .run(&db_pool)
        .await
        .map_err(|e| {
            tracing::error!("Failed to run migrations: {}", e);
            crate::error::AppError::Internal(format!("Migration failed: {}", e))
        })?;

    tracing::info!(
        "Initializing Redis/Valkey connection pool (max: {})",
        settings.redis_pool_max
    );
    let redis_config = RedisConfig::from_url(&settings.redis_url);
    let redis_pool = redis_config
        .builder()
        .map_err(|e| {
            tracing::error!("Failed to create Redis pool builder: {}", e);
            crate::error::AppError::Internal(format!("Redis pool config failed: {}", e))
        })?
        .max_size(settings.redis_pool_max)
        .runtime(Runtime::Tokio1)
        .build()
        .map_err(|e| {
            tracing::error!("Failed to create Redis pool: {}", e);
            crate::error::AppError::Internal(format!("Redis pool creation failed: {}", e))
        })?;

    let state = AppState::new(db_pool, redis_pool, settings);

    tracing::info!("Building application router");
    let app = build_router(state);

    Ok(app)
}

/// Builds the Axum router with all routes and middleware.
///
/// Params: Application state.
/// Logic: Configures CORS based on environment, applies tracing and compression.
/// Returns: Configured router.
fn build_router(state: AppState) -> Router {
    // CORS Configuration:
    // - Development: Permissive for testing with web tools
    // - Production: Deny all origins (mobile apps bypass CORS anyway)
    let cors = match state.config.environment {
        crate::config::AppEnvironment::Development => {
            tracing::info!("CORS: Permissive (development mode)");
            CorsLayer::new()
                .allow_origin(Any)
                .allow_methods(Any)
                .allow_headers(Any)
        }
        crate::config::AppEnvironment::Production => {
            // Strict: No origins allowed. Mobile apps don't use CORS.
            // If a web admin panel is needed, specific origins will be added here.
            tracing::info!("CORS: Strict (production mode - no web origins allowed)");
            CorsLayer::new()
                // allow_origin with empty list = deny all
                .allow_methods([
                    axum::http::Method::GET,
                    axum::http::Method::POST,
                    axum::http::Method::PUT,
                    axum::http::Method::DELETE,
                    axum::http::Method::OPTIONS,
                ])
                .allow_headers([
                    axum::http::header::AUTHORIZATION,
                    axum::http::header::CONTENT_TYPE,
                    axum::http::header::HeaderName::from_static("x-master-password"),
                ])
        }
    };

    let mut router = Router::new()
        .nest("/api/v1", routes::api_routes(state.clone()))
        .layer(CompressionLayer::new())
        .layer(TraceLayer::new_for_http())
        .layer(axum::extract::DefaultBodyLimit::max(5 * 1024 * 1024)) // 5MB Limit
        .layer(cors)
        .with_state(state.clone());

    // Mount API Docs (Scalar) only in Development environment
    if state.config.environment == crate::config::AppEnvironment::Development {
        use crate::docs::ApiDoc;
        use utoipa::OpenApi;
        use utoipa_scalar::*;

        tracing::info!("Enabling API Documentation at /docs");
        router = router.merge(Scalar::with_url("/docs", ApiDoc::openapi()));
    }

    router
}
