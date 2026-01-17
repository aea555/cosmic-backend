//! Core business logic layer.
//!
//! This module contains the domain logic separated from HTTP concerns.
//! All sensitive operations run in blocking tasks to avoid blocking the async runtime.

pub mod auth;
pub mod crypto;
pub mod vault;
