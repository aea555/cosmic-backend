//! Cosmic Backend - Zero-Knowledge Password Manager API
//!
//! This is the main entry point for the application. It initializes logging,
//! loads configuration, and starts the HTTP server.

mod app;
mod cache;
mod config;
mod core;
mod docs;
mod error;
mod handlers;
mod middleware;
mod repository;
mod routes;
mod state;
mod types;

use tracing_subscriber::{layer::SubscriberExt, util::SubscriberInitExt};

/// Application entry point.
///
/// Params: None.
/// Logic: Loads env vars, initializes tracing, builds app, starts server.
/// Returns: Exit code (0 on success).
#[tokio::main]
async fn main() {
    // Load environment variables from .env file if present
    if let Err(e) = dotenvy::dotenv() {
        eprintln!("Warning: Could not load .env file: {}", e);
    }

    // Initialize tracing subscriber for structured logging
    tracing_subscriber::registry()
        .with(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info,cosmic_backend=debug".into()),
        )
        .with(tracing_subscriber::fmt::layer())
        .init();

    tracing::info!("Starting Cosmic Backend - Zero-Knowledge Password Manager API");

    // Load configuration from environment
    let settings = match config::Settings::from_env() {
        Ok(s) => s,
        Err(e) => {
            tracing::error!("Failed to load configuration: {}", e);
            std::process::exit(1);
        }
    };

    let addr = settings.server_addr();
    tracing::info!("Server will bind to {}", addr);

    // Build the application
    let app = match app::build_app(settings).await {
        Ok(app) => app,
        Err(e) => {
            tracing::error!("Failed to build application: {}", e);
            std::process::exit(1);
        }
    };

    // Create TCP listener
    let listener = match tokio::net::TcpListener::bind(&addr).await {
        Ok(l) => l,
        Err(e) => {
            tracing::error!("Failed to bind to {}: {}", addr, e);
            std::process::exit(1);
        }
    };

    tracing::info!("Server listening on http://{}", addr);

    // Start serving requests
    if let Err(e) = axum::serve(listener, app).await {
        tracing::error!("Server error: {}", e);
        std::process::exit(1);
    }
}
