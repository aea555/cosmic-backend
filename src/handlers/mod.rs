//! HTTP handlers for all API endpoints.
//!
//! This module provides thin handlers that parse HTTP requests, validate input,
//! delegate to core logic, and format responses.

pub mod account;
pub mod auth;
pub mod email;
pub mod items;
pub mod notes;
pub mod secrets;
