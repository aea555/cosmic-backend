//! Rate limiting middleware.
//!
//! This module provides IP-based rate limiting for public routes and
//! user-based rate limiting for protected routes. Uses Redis for distributed
//! state to work across multiple API instances.

use crate::error::{AppError, AppResult};
use crate::types::UserId;
use axum::{
    body::Body,
    extract::State,
    http::{Request, StatusCode},
    middleware::Next,
    response::Response,
};
use deadpool_redis::{Pool as RedisPool, redis::AsyncCommands};

/// Rate limit configuration for different endpoint categories.
#[derive(Debug, Clone, Copy)]
pub struct RateLimitConfig {
    /// Maximum requests allowed in the window.
    pub max_requests: u32,
    /// Time window in seconds.
    pub window_seconds: u64,
}

impl RateLimitConfig {
    /// Creates a new rate limit configuration.
    pub const fn new(max_requests: u32, window_seconds: u64) -> Self {
        Self {
            max_requests,
            window_seconds,
        }
    }
}

/// Rate limit configurations for different endpoint types.
pub mod limits {
    use super::RateLimitConfig;

    /// Strict limit for authentication endpoints (login, register).
    /// 5 requests per minute - prevents brute force attacks.
    pub const AUTH_STRICT: RateLimitConfig = RateLimitConfig::new(5, 60);

    /// Medium limit for sensitive operations (refresh, verify-email).
    /// 10 requests per minute.
    pub const AUTH_MEDIUM: RateLimitConfig = RateLimitConfig::new(10, 60);

    /// Standard limit for general public endpoints.
    /// 60 requests per minute.
    #[allow(dead_code)] // For future use with public non-auth endpoints
    pub const PUBLIC_STANDARD: RateLimitConfig = RateLimitConfig::new(60, 60);

    /// Protected route limit (per user, not IP).
    /// 100 requests per minute.
    pub const PROTECTED_USER: RateLimitConfig = RateLimitConfig::new(100, 60);

    /// Global IP-based limit for all endpoints.
    /// 200 requests per minute - catches aggressive scrapers.
    #[allow(dead_code)] // For future use as global middleware
    pub const GLOBAL_IP: RateLimitConfig = RateLimitConfig::new(200, 60);
}

/// Extracts the client IP address from the request.
///
/// Params: Request reference.
/// Logic: Checks headers in order of trust:
///   1. CF-Connecting-IP (Cloudflare Tunnel - most trusted)
///   2. X-Real-IP (nginx - trusted, set by our nginx config)
///   3. X-Forwarded-For (generic proxy - less trusted, takes first IP)
///   4. Peer address (direct connection fallback)
///
/// SECURITY NOTE: When behind nginx, the nginx config overwrites X-Real-IP
/// and X-Forwarded-For with the actual client IP, preventing spoofing.
/// Returns: IP address as string for rate limit key.
pub fn extract_client_ip(request: &Request<Body>) -> String {
    // Priority 1: CF-Connecting-IP (Cloudflare Tunnel provides this)
    if let Some(cf_ip) = request.headers().get("cf-connecting-ip") {
        if let Ok(value) = cf_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    // Priority 2: X-Real-IP (nginx sets this from $remote_addr or CF header)
    if let Some(real_ip) = request.headers().get("x-real-ip") {
        if let Ok(value) = real_ip.to_str() {
            let ip = value.trim();
            if !ip.is_empty() {
                return ip.to_string();
            }
        }
    }

    // Priority 3: X-Forwarded-For (take first IP in chain)
    if let Some(forwarded) = request.headers().get("x-forwarded-for") {
        if let Ok(value) = forwarded.to_str() {
            if let Some(ip) = value.split(',').next() {
                let ip = ip.trim();
                if !ip.is_empty() {
                    return ip.to_string();
                }
            }
        }
    }

    // Priority 4: Fallback to connection peer address
    request
        .extensions()
        .get::<std::net::SocketAddr>()
        .map(|addr| addr.ip().to_string())
        .unwrap_or_else(|| "unknown".to_string())
}

/// Checks if a request should be rate limited.
///
/// Params: Redis pool, key prefix, identifier, rate limit config.
/// Logic: Implements sliding window counter using Redis INCR + EXPIRE.
/// Returns: Ok(remaining) if allowed, Err(RateLimited) if limit exceeded.
pub async fn check_rate_limit(
    pool: &RedisPool,
    prefix: &str,
    identifier: &str,
    config: RateLimitConfig,
) -> AppResult<u32> {
    let key = format!("ratelimit:{}:{}", prefix, identifier);

    let mut conn = pool
        .get()
        .await
        .map_err(|e| AppError::Internal(format!("Redis connection failed: {}", e)))?;

    // Increment counter and get current value
    let count: u32 = conn
        .incr(&key, 1)
        .await
        .map_err(|e| AppError::Internal(format!("Redis INCR failed: {}", e)))?;

    // Set expiration on first request in window
    if count == 1 {
        let _: () = conn
            .expire(&key, config.window_seconds as i64)
            .await
            .map_err(|e| AppError::Internal(format!("Redis EXPIRE failed: {}", e)))?;
    }

    if count > config.max_requests {
        return Err(AppError::RateLimited {
            retry_after_seconds: config.window_seconds,
        });
    }

    Ok(config.max_requests.saturating_sub(count))
}

/// Global IP-based rate limiting middleware.
///
/// Params: Redis pool, request, next middleware.
/// Logic: Applies global IP rate limit to all requests.
/// Returns: Response or 429 Too Many Requests.
#[allow(dead_code)] // For future use as global middleware layer
pub async fn global_rate_limit(
    State(pool): State<RedisPool>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let ip = extract_client_ip(&request);

    match check_rate_limit(&pool, "global", &ip, limits::GLOBAL_IP).await {
        Ok(_remaining) => Ok(next.run(request).await),
        Err(AppError::RateLimited {
            retry_after_seconds,
        }) => {
            tracing::warn!("Global rate limit exceeded for IP: {}", ip);
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit exceeded. Retry after {} seconds.",
                    retry_after_seconds
                ),
            ))
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            // Fail open - allow request if Redis is down
            Ok(next.run(request).await)
        }
    }
}

/// Strict rate limiting for authentication endpoints (login, register).
///
/// Params: Redis pool, request, next middleware.
/// Logic: Applies strict per-IP limit for auth endpoints.
/// Returns: Response or 429 Too Many Requests.
pub async fn auth_strict_rate_limit(
    State(pool): State<RedisPool>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let ip = extract_client_ip(&request);

    match check_rate_limit(&pool, "auth:strict", &ip, limits::AUTH_STRICT).await {
        Ok(_remaining) => Ok(next.run(request).await),
        Err(AppError::RateLimited {
            retry_after_seconds,
        }) => {
            tracing::warn!("Auth strict rate limit exceeded for IP: {}", ip);
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Too many authentication attempts. Please wait {} seconds.",
                    retry_after_seconds
                ),
            ))
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            Ok(next.run(request).await)
        }
    }
}

/// Medium rate limiting for sensitive operations (refresh, verify-email).
///
/// Params: Redis pool, request, next middleware.
/// Logic: Applies medium per-IP limit.
/// Returns: Response or 429 Too Many Requests.
pub async fn auth_medium_rate_limit(
    State(pool): State<RedisPool>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    let ip = extract_client_ip(&request);

    match check_rate_limit(&pool, "auth:medium", &ip, limits::AUTH_MEDIUM).await {
        Ok(_remaining) => Ok(next.run(request).await),
        Err(AppError::RateLimited {
            retry_after_seconds,
        }) => {
            tracing::warn!("Auth medium rate limit exceeded for IP: {}", ip);
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit exceeded. Retry after {} seconds.",
                    retry_after_seconds
                ),
            ))
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            Ok(next.run(request).await)
        }
    }
}

/// User-based rate limiting for protected routes.
///
/// Params: Redis pool, request, next middleware.
/// Logic: Extracts user ID from JWT extensions, applies per-user limit.
/// Returns: Response or 429 Too Many Requests.
///
/// Note: This middleware must be applied AFTER JWT authentication middleware.
pub async fn user_rate_limit(
    State(pool): State<RedisPool>,
    request: Request<Body>,
    next: Next,
) -> Result<Response, (StatusCode, String)> {
    // Get user ID from request extensions (set by JWT middleware)
    let user_id = request
        .extensions()
        .get::<UserId>()
        .map(|id| id.to_string())
        .unwrap_or_else(|| {
            // Fallback to IP if no user ID (shouldn't happen on protected routes)
            extract_client_ip(&request)
        });

    match check_rate_limit(&pool, "user", &user_id, limits::PROTECTED_USER).await {
        Ok(_remaining) => Ok(next.run(request).await),
        Err(AppError::RateLimited {
            retry_after_seconds,
        }) => {
            tracing::warn!("User rate limit exceeded for user: {}", user_id);
            Err((
                StatusCode::TOO_MANY_REQUESTS,
                format!(
                    "Rate limit exceeded. Retry after {} seconds.",
                    retry_after_seconds
                ),
            ))
        }
        Err(e) => {
            tracing::error!("Rate limit check failed: {}", e);
            Ok(next.run(request).await)
        }
    }
}
