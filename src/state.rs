//! Application state shared across all handlers.
//!
//! This module defines the AppState struct that holds all infrastructure handles
//! (database pool, cache pool, configuration). It is injected into handlers via
//! Axum's State extractor.

use crate::config::Settings;
use deadpool_redis::Pool as RedisPool;
use sqlx::PgPool;
use std::sync::Arc;

/// Thread-safe application state shared across all request handlers.
///
/// Params: Contains database pool, cache pool, and configuration.
/// Logic: Cloned for each request (Arc makes this cheap).
/// Returns: Shared application resources.
#[derive(Clone)]
pub struct AppState {
    /// PostgreSQL connection pool.
    pub db: PgPool,
    /// Redis/Valkey connection pool for caching.
    #[allow(dead_code)] // Reserved for cache layer integration
    pub cache: RedisPool,
    /// Application configuration.
    pub config: Arc<Settings>,
}

impl AppState {
    /// Creates a new AppState instance.
    ///
    /// Params: Database pool, Redis pool, and settings.
    /// Logic: Wraps settings in Arc for cheap cloning.
    /// Returns: New AppState.
    #[must_use]
    pub fn new(db: PgPool, cache: RedisPool, config: Settings) -> Self {
        Self {
            db,
            cache,
            config: Arc::new(config),
        }
    }
}

impl std::fmt::Debug for AppState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("AppState")
            .field("db", &"PgPool")
            .field("cache", &"RedisPool")
            .field("config", &"Settings")
            .finish()
    }
}
