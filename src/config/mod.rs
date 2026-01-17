//! Application configuration management.
//!
//! This module provides layered configuration loading from environment variables.
//! All configuration is validated at startup to fail fast on misconfiguration.

use secrecy::{ExposeSecret, SecretString};
use serde::Deserialize;

/// Application settings loaded from environment variables.
///
/// All required configuration must be present at startup or the application
/// will fail to start with a descriptive error message.
#[derive(Debug, Deserialize, Clone, PartialEq, Eq)]
#[serde(rename_all = "lowercase")]
pub enum AppEnvironment {
    Development,
    Production,
}

#[derive(Debug, Deserialize, Clone)]
pub struct Settings {
    /// Current application environment
    #[serde(default = "default_environment")]
    pub environment: AppEnvironment,
    /// PostgreSQL connection URL.
    pub database_url: SecretString,
    /// Redis/Valkey connection URL.
    pub redis_url: String,
    /// Secret key for JWT signing (minimum 32 characters).
    pub jwt_secret: SecretString,
    /// JWT access token expiry in seconds (default: 900 = 15 minutes).
    #[serde(default = "default_jwt_expiry")]
    pub jwt_expiry_seconds: i64,
    /// Refresh token expiry in days (default: 30).
    #[serde(default = "default_refresh_expiry")]
    pub refresh_token_expiry_days: i64,
    /// Server bind host (default: 0.0.0.0).
    #[serde(default = "default_host")]
    pub server_host: String,
    /// Server bind port (default: 8080).
    #[serde(default = "default_port")]
    pub server_port: u16,
    /// Application base URL for email links.
    pub app_url: String,

    // Email configuration (Mailtrap)
    /// Mailtrap API token for sending emails.
    #[serde(rename = "email__mailtrap_api_token")]
    pub mailtrap_api_token: SecretString,
    /// From email address for outgoing emails.
    #[serde(rename = "email__from_email")]
    pub email_from_email: String,
    /// From name for outgoing emails.
    #[serde(rename = "email__from_name", default = "default_from_name")]
    pub email_from_name: String,
    /// Reply-to email address.
    #[serde(rename = "email__reply_to_email")]
    pub email_reply_to: String,

    /// Mobile app deep link scheme (e.g., "cosmicvault://").
    /// Used to redirect email verification links to the mobile app.
    #[serde(default = "default_mobile_deep_link_scheme")]
    pub mobile_deep_link_scheme: String,

    /// Web frontend URL (e.g., "https://www.cosmicvault.com").
    /// Used to redirect email verification links for desktop/web users.
    #[serde(default = "default_web_frontend_url")]
    pub web_frontend_url: String,

    // -------------------------------------------------------------------------
    // Concurrency & Pool Configuration
    // -------------------------------------------------------------------------
    /// Maximum number of database connections in the pool.
    /// Default: 20
    #[serde(default = "default_database_pool_max")]
    pub database_pool_max: u32,

    /// Database connection acquire timeout in seconds.
    /// Default: 5
    #[serde(default = "default_database_acquire_timeout")]
    pub database_acquire_timeout_secs: u64,

    /// Maximum number of Redis/Valkey connections in the pool.
    /// Default: 16
    #[serde(default = "default_redis_pool_max")]
    pub redis_pool_max: usize,

    /// Number of async worker threads.
    /// Default: 0 (auto-detect based on CPU cores)
    /// Set to 0 to use the number of CPU cores.
    /// Note: Uses WORKER_THREADS env var to avoid conflict with Tokio's built-in TOKIO_WORKER_THREADS.
    #[serde(default = "default_worker_threads")]
    pub worker_threads: usize,
}

fn default_jwt_expiry() -> i64 {
    900
}

fn default_refresh_expiry() -> i64 {
    30
}

fn default_host() -> String {
    "0.0.0.0".to_string()
}

fn default_port() -> u16 {
    8080
}

fn default_from_name() -> String {
    "CLBIO".to_string()
}

fn default_environment() -> AppEnvironment {
    AppEnvironment::Development
}

fn default_mobile_deep_link_scheme() -> String {
    "cosmicvault://".to_string()
}

fn default_web_frontend_url() -> String {
    "https://vault.cosmicvault.com".to_string()
}

fn default_database_pool_max() -> u32 {
    20
}

fn default_database_acquire_timeout() -> u64 {
    5
}

fn default_redis_pool_max() -> usize {
    16
}

/// Default to 0, which means "auto-detect based on CPU cores".
fn default_worker_threads() -> usize {
    0
}

impl Settings {
    /// Loads settings from environment variables.
    ///
    /// Params: None.
    /// Logic: Reads all required env vars and validates their values.
    /// Returns: Settings instance or error if configuration is invalid.
    ///
    /// # Errors
    /// Returns error if required environment variables are missing or invalid.
    pub fn from_env() -> Result<Self, config::ConfigError> {
        let settings = config::Config::builder()
            .add_source(config::Environment::default().try_parsing(true))
            .build()?;

        let settings: Settings = settings.try_deserialize()?;
        settings.validate()?;
        Ok(settings)
    }

    /// Validates the loaded settings.
    ///
    /// Params: Self reference.
    /// Logic: Checks JWT secret length and other constraints.
    /// Returns: Ok if valid, Err with description if invalid.
    fn validate(&self) -> Result<(), config::ConfigError> {
        if self.jwt_secret.expose_secret().len() < 32 {
            return Err(config::ConfigError::Message(
                "JWT_SECRET must be at least 32 characters".to_string(),
            ));
        }

        if self.jwt_expiry_seconds < 60 {
            return Err(config::ConfigError::Message(
                "JWT_EXPIRY_SECONDS must be at least 60".to_string(),
            ));
        }

        if self.refresh_token_expiry_days < 1 {
            return Err(config::ConfigError::Message(
                "REFRESH_TOKEN_EXPIRY_DAYS must be at least 1".to_string(),
            ));
        }

        if self.mailtrap_api_token.expose_secret().is_empty() {
            return Err(config::ConfigError::Message(
                "EMAIL__MAILTRAP_API_TOKEN must be set".to_string(),
            ));
        }

        Ok(())
    }

    /// Returns the full server address for binding.
    ///
    /// Params: None.
    /// Logic: Combines host and port.
    /// Returns: Address string in format "host:port".
    #[must_use]
    pub fn server_addr(&self) -> String {
        format!("{}:{}", self.server_host, self.server_port)
    }
}
