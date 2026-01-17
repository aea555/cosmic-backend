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
    tracing::info!("Initializing database connection pool");
    let db_pool = PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(Duration::from_secs(5))
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

    tracing::info!("Initializing Redis/Valkey connection pool");
    let redis_config = RedisConfig::from_url(&settings.redis_url);
    let redis_pool = redis_config
        .create_pool(Some(Runtime::Tokio1))
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
