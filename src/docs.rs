use utoipa::OpenApi;

use crate::types::*;

/// OpenAPI documentation definition.
#[derive(OpenApi)]
#[openapi(
    paths(
        // Auth handlers
        crate::handlers::auth::register,
        crate::handlers::auth::login,
        crate::handlers::auth::verify_email,
        crate::handlers::auth::refresh,
        crate::handlers::auth::logout,
        
        // Secrets handlers
        crate::handlers::secrets::list_secrets,
        crate::handlers::secrets::create_secret,
        crate::handlers::secrets::get_secret,
        crate::handlers::secrets::update_secret,
        crate::handlers::secrets::delete_secret,
        crate::handlers::secrets::favorite_secret,
        crate::handlers::secrets::unfavorite_secret,

        // Notes handlers
        crate::handlers::notes::list_notes,
        crate::handlers::notes::create_note,
        crate::handlers::notes::get_note,
        crate::handlers::notes::update_note,
        crate::handlers::notes::delete_note,
        crate::handlers::notes::favorite_note,
        crate::handlers::notes::unfavorite_note,

        // Items handlers (bulk operations)
        crate::handlers::items::bulk_create,
        crate::handlers::items::bulk_delete,
        crate::handlers::items::bulk_favorite,
        crate::handlers::items::bulk_unfavorite,

        // Account handlers
        crate::handlers::account::request_delete_account,
        crate::handlers::account::confirm_delete_account,
        crate::handlers::account::request_change_password,
        crate::handlers::account::confirm_change_password,
        crate::handlers::account::request_change_email,
        crate::handlers::account::confirm_change_email,
    ),
    components(
        schemas(
            // Domain types
            RegisterRequest,
            LoginRequest,
            VerifyEmailRequest,
            RefreshRequest,
            AuthResponse,
            CreateSecretRequest,
            UpdateSecretRequest,
            SecretResponse,
            CreateNoteRequest,
            UpdateNoteRequest,
            NoteResponse,
            UserId,
            SecretId,
            NoteId,
            
            // Bulk operations
            ItemType,
            BulkCreateItem,
            BulkCreateRequest,
            BulkCreateResultItem,
            BulkCreateResponse,
            BulkDeleteItem,
            BulkDeleteRequest,
            BulkDeleteResponse,
            BulkFavoriteItem,
            BulkFavoriteRequest,
            BulkFavoriteResponse,

            // Account management
            DeleteAccountRequest,
            ConfirmDeleteAccountRequest,
            ChangePasswordRequest,
            ConfirmChangePasswordRequest,
            ChangeEmailRequest,
            ConfirmChangeEmailRequest,
            
            // Response wrappers
            AuthResponseWrapper,
            SecretResponseWrapper,
            SecretListResponseWrapper,
            NoteResponseWrapper,
            NoteListResponseWrapper,
            EmptyResponseWrapper,
            BulkCreateResponseWrapper,
            BulkDeleteResponseWrapper,
            BulkFavoriteResponseWrapper,
        )
    ),
    tags(
        (name = "auth", description = "Authentication endpoints"),
        (name = "secrets", description = "Secret management endpoints"),
        (name = "notes", description = "Secure note management endpoints"),
        (name = "items", description = "Bulk operations for secrets and notes"),
        (name = "account", description = "Account management endpoints")
    ),
    modifiers(&SecurityAddon)
)]
pub struct ApiDoc;

use utoipa::openapi::security::{ApiKey, ApiKeyValue, SecurityScheme};
use utoipa::Modify;

struct SecurityAddon;

impl Modify for SecurityAddon {
    fn modify(&self, openapi: &mut utoipa::openapi::OpenApi) {
        if let Some(components) = openapi.components.as_mut() {
            // Add Bearer Token security
            components.add_security_scheme(
                "bearer_auth",
                SecurityScheme::Http(
                    utoipa::openapi::security::HttpBuilder::new()
                        .scheme(utoipa::openapi::security::HttpAuthScheme::Bearer)
                        .bearer_format("JWT")
                        .build(),
                ),
            );

            // Add X-Master-Password security
            components.add_security_scheme(
                "master_password_auth",
                SecurityScheme::ApiKey(ApiKey::Header(ApiKeyValue::new("X-Master-Password"))),
            );
        }
    }
}
