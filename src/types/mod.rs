//! Strongly-typed domain types using the Newtype pattern.
//!
//! This module defines wrapper types that prevent accidental mixing of semantically
//! different values (e.g., UserId vs SecretId). All sensitive data uses secrecy
//! wrappers for automatic memory zeroing.

#![allow(dead_code)] // Library types with methods for future expansion

use secrecy::{ExposeSecret, SecretBox, SecretString};
use serde::{Deserialize, Serialize};
use sqlx::FromRow;
use utoipa::ToSchema;
use uuid::Uuid;

/// Unique identifier for a user.
///
/// Params: Wraps a UUID v4.
/// Logic: Using Newtype pattern prevents accidental use of SecretId where UserId is expected.
/// Returns: An opaque user identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(transparent)]
#[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
pub struct UserId(pub Uuid);

impl UserId {
    /// Creates a new random UserId.
    ///
    /// Params: None.
    /// Logic: Generates a UUID v4.
    /// Returns: A new unique UserId.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the inner UUID value.
    ///
    /// Params: None.
    /// Logic: Exposes the wrapped UUID.
    /// Returns: The inner UUID.
    #[must_use]
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for UserId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a secret entry.
///
/// Params: Wraps a UUID v4.
/// Logic: Using Newtype pattern prevents accidental use of UserId where SecretId is expected.
/// Returns: An opaque secret identifier.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(transparent)]
#[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
pub struct SecretId(pub Uuid);

impl SecretId {
    /// Creates a new random SecretId.
    ///
    /// Params: None.
    /// Logic: Generates a UUID v4.
    /// Returns: A new unique SecretId.
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    /// Returns the inner UUID value.
    ///
    /// Params: None.
    /// Logic: Exposes the wrapped UUID.
    /// Returns: The inner UUID.
    #[must_use]
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for SecretId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for SecretId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// Unique identifier for a note entry.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, sqlx::Type, ToSchema)]
#[sqlx(transparent)]
#[schema(value_type = String, example = "550e8400-e29b-41d4-a716-446655440000")]
pub struct NoteId(pub Uuid);

impl NoteId {
    #[must_use]
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }

    #[must_use]
    pub fn into_inner(self) -> Uuid {
        self.0
    }
}

impl Default for NoteId {
    fn default() -> Self {
        Self::new()
    }
}

impl std::fmt::Display for NoteId {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}", self.0)
    }
}

/// A cryptographic salt used for key derivation.
///
/// Params: Wraps a 32-byte array.
/// Logic: Fixed-size salt for Argon2id key derivation.
/// Returns: Salt bytes.
#[derive(Debug, Clone)]
pub struct Salt(pub [u8; 32]);

impl Salt {
    /// Returns the salt as a byte slice.
    ///
    /// Params: None.
    /// Logic: Exposes the salt bytes.
    /// Returns: Reference to salt bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }
}

impl From<[u8; 32]> for Salt {
    fn from(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }
}

impl TryFrom<Vec<u8>> for Salt {
    type Error = String;

    fn try_from(bytes: Vec<u8>) -> Result<Self, Self::Error> {
        let arr: [u8; 32] = bytes
            .try_into()
            .map_err(|v: Vec<u8>| format!("Expected 32 bytes, got {}", v.len()))?;
        Ok(Self(arr))
    }
}

/// The Master Key derived from user's password.
///
/// Params: Wraps a 32-byte key in a SecretBox for automatic memory zeroing.
/// Logic: Never stored to disk. Exists only in request context and momentary RAM.
/// Returns: The derived encryption key.
pub struct MasterKey(SecretBox<[u8; 32]>);

impl MasterKey {
    /// Creates a MasterKey from raw bytes.
    ///
    /// Params: 32-byte key array.
    /// Logic: Wraps in SecretBox for automatic memory zeroing on drop.
    /// Returns: A new MasterKey.
    #[must_use]
    pub fn new(key: [u8; 32]) -> Self {
        Self(SecretBox::new(Box::new(key)))
    }

    /// Exposes the key bytes for cryptographic operations.
    ///
    /// Params: None.
    /// Logic: Returns a reference to the key bytes.
    /// Returns: Reference to the 32-byte key.
    #[must_use]
    pub fn expose(&self) -> &[u8; 32] {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for MasterKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "MasterKey([REDACTED])")
    }
}

/// Encrypted data blob with nonce prepended.
///
/// Params: Raw bytes containing nonce + ciphertext.
/// Logic: Format is 12-byte nonce followed by ChaCha20-Poly1305 ciphertext.
/// Returns: Encrypted bytes.
#[derive(Debug, Clone)]
pub struct EncryptedBlob(pub Vec<u8>);

impl EncryptedBlob {
    /// Creates an EncryptedBlob from raw bytes.
    ///
    /// Params: Raw encrypted bytes.
    /// Logic: Stores bytes as-is.
    /// Returns: A new EncryptedBlob.
    #[must_use]
    pub fn new(bytes: Vec<u8>) -> Self {
        Self(bytes)
    }

    /// Returns the encrypted bytes.
    ///
    /// Params: None.
    /// Logic: Exposes the encrypted bytes.
    /// Returns: Reference to encrypted bytes.
    #[must_use]
    pub fn as_bytes(&self) -> &[u8] {
        &self.0
    }

    /// Consumes self and returns the inner bytes.
    ///
    /// Params: None.
    /// Logic: Returns owned bytes.
    /// Returns: The encrypted bytes.
    #[must_use]
    pub fn into_bytes(self) -> Vec<u8> {
        self.0
    }
}

/// A password wrapped in SecretString for automatic zeroing.
///
/// Params: Password string wrapped in SecretString.
/// Logic: Prevents accidental logging or display of password.
/// Returns: The password wrapper.
pub struct Password(SecretString);

impl Password {
    /// Creates a Password from a string.
    ///
    /// Params: Raw password string.
    /// Logic: Wraps in SecretString for protection.
    /// Returns: A new Password.
    #[must_use]
    pub fn new(password: String) -> Self {
        Self(SecretString::from(password))
    }

    /// Exposes the password for cryptographic operations.
    ///
    /// Params: None.
    /// Logic: Returns the password string.
    /// Returns: Reference to the password.
    #[must_use]
    pub fn expose(&self) -> &str {
        self.0.expose_secret()
    }
}

impl std::fmt::Debug for Password {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "Password([REDACTED])")
    }
}

/// User entity from database.
///
/// Params: Contains user data including encrypted canary.
/// Logic: No password hash is stored per Zero-Knowledge architecture.
/// Returns: User record.
#[derive(Debug, Clone, FromRow)]
pub struct User {
    pub id: Uuid,
    pub email: String,
    pub salt: Vec<u8>,
    pub encrypted_canary: Vec<u8>,
    pub email_verified: bool,
    pub token_version: i32,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Email verification token entity from database.
///
/// Params: Contains verification token data.
/// Logic: Used for email verification during registration.
/// Returns: Verification token record.
#[derive(Debug, Clone, FromRow)]
pub struct EmailVerificationToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Secret entity from database.
///
/// Params: Contains encrypted secret data.
/// Logic: All data is encrypted with user's Master Key.
/// Returns: Secret record.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Secret {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub is_favorite: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Note entity from database.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct Note {
    pub id: Uuid,
    pub user_id: Uuid,
    pub encrypted_data: Vec<u8>,
    pub is_favorite: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// OTP request entity from database.
///
/// Params: Contains OTP hash and request metadata.
/// Logic: Used for account deletion, password change, email change.
/// Returns: OTP request record.
#[derive(Debug, Clone, FromRow)]
pub struct OtpRequest {
    pub id: Uuid,
    pub user_id: Uuid,
    pub otp_hash: Vec<u8>,
    pub request_type: String,
    pub new_email: Option<String>,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Item type for bulk operations.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, ToSchema)]
#[serde(rename_all = "snake_case")]
pub enum ItemType {
    Secret,
    Note,
}

impl std::fmt::Display for ItemType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ItemType::Secret => write!(f, "secret"),
            ItemType::Note => write!(f, "note"),
        }
    }
}

/// Refresh token entity from database.
///
/// Params: Contains hashed refresh token data.
/// Logic: Token is hashed with SHA-256 before storage.
/// Returns: Refresh token record.
#[derive(Debug, Clone, FromRow)]
pub struct RefreshToken {
    pub id: Uuid,
    pub user_id: Uuid,
    pub token_hash: Vec<u8>,
    pub used: bool,
    pub expires_at: chrono::DateTime<chrono::Utc>,
    pub created_at: chrono::DateTime<chrono::Utc>,
}

/// Validates password complexity:
/// - At least 1 uppercase letter
/// - At least 1 lowercase letter
/// - At least 1 number
/// - At least 1 special character (non-alphanumeric)
fn validate_password_complexity(password: &str) -> Result<(), validator::ValidationError> {
    let has_uppercase = password.chars().any(|c| c.is_uppercase());
    let has_lowercase = password.chars().any(|c| c.is_lowercase());
    let has_number = password.chars().any(|c| c.is_numeric());
    let has_special = password.chars().any(|c| !c.is_alphanumeric());

    if has_uppercase && has_lowercase && has_number && has_special {
        Ok(())
    } else {
        let mut error = validator::ValidationError::new("invalid_password_complexity");
        error.message = Some(
            "Password must contain at least 1 uppercase, 1 lowercase, 1 number, and 1 special character"
                .into(),
        );
        Err(error)
    }
}

/// Request payload for user registration.
///
/// Params: Email and master password.
/// Logic: Validated before processing.
/// Returns: Registration request.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct RegisterRequest {
    #[validate(
        email(message = "Invalid email format"),
        length(max = 320, message = "Email must be at most 320 characters")
    )]
    pub email: String,
    #[validate(
        length(
            min = 12,
            max = 256,
            message = "Password must be between 12 and 256 characters"
        ),
        custom(function = "validate_password_complexity")
    )]
    pub password: String,
}

/// Request payload for email verification.
///
/// Params: Verification token from email link.
/// Logic: Token is validated against database.
/// Returns: Verification request.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct VerifyEmailRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub token: String,
}

/// Request payload for resending verification email.
///
/// Params: Email address.
/// Logic: Generates new verification token if no active token exists.
/// Returns: Resend request.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct ResendVerificationRequest {
    #[validate(
        email(message = "Invalid email format"),
        length(max = 320, message = "Email must be at most 320 characters")
    )]
    pub email: String,
}

/// Request payload for user login.
///
/// Params: Email and master password.
/// Logic: Password is used to derive Master Key and verify Canary.
/// Returns: Login request.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct LoginRequest {
    #[validate(
        email(message = "Invalid email format"),
        length(max = 320, message = "Email must be at most 320 characters")
    )]
    pub email: String,
    #[validate(length(max = 256, message = "Password too long"))]
    pub password: String,
}

/// Response payload for successful authentication.
///
/// Params: Access token (JWT) and refresh token.
/// Logic: Access token expires in 15 minutes, refresh token in 30 days.
/// Returns: Authentication tokens.
#[derive(Debug, Serialize, ToSchema)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub token_type: String,
    pub expires_in: i64,
}

/// Request payload for token refresh.
///
/// Params: Refresh token string.
/// Logic: Token is rotated on each use.
/// Returns: Refresh request.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct RefreshRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
}

/// Validates that a secret has at least one identifier (title, username, email, url, password, or telephone_number).
fn validate_secret_requirements(
    request: &CreateSecretRequest,
) -> Result<(), validator::ValidationError> {
    if request.title.is_some()
        || request.username.is_some()
        || request.email.is_some()
        || request.url.is_some()
        || request.password.is_some()
        || request.telephone_number.is_some()
    {
        Ok(())
    } else {
        let mut error = validator::ValidationError::new("missing_required_fields");
        error.message = Some(
            "Secret must have at least a title, username, email, URL, password, or telephone number"
                .into(),
        );
        Err(error)
    }
}

/// Request payload for creating a new secret.
///
/// Params: Secret data to be encrypted.
/// Logic: Data is encrypted with Master Key before storage.
/// Returns: Create secret request.
#[derive(Debug, Deserialize, Serialize, validator::Validate, ToSchema)]
#[validate(schema(function = "validate_secret_requirements"))]
pub struct CreateSecretRequest {
    #[validate(length(min = 1, max = 256, message = "Title must be 1-256 characters"))]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 255, message = "Username must be at most 255 characters"))]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(
        email(message = "Invalid email format"),
        length(max = 320, message = "Email must be at most 320 characters")
    )]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 20, message = "Telephone number must be at most 20 characters"))]
    pub telephone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2048, message = "Password too long"))]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(
        url(message = "Invalid URL format"),
        length(max = 2048, message = "URL must be at most 2048 characters")
    )]
    pub url: Option<String>,
}

/// Request payload for updating an existing secret.
///
/// Params: Updated secret data.
/// Logic: Data is re-encrypted with Master Key.
/// Returns: Update secret request.
#[derive(Debug, Deserialize, Serialize, validator::Validate, ToSchema)]
pub struct UpdateSecretRequest {
    #[validate(length(min = 1, max = 256, message = "Title must be 1-256 characters"))]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 255, message = "Username must be at most 255 characters"))]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(
        email(message = "Invalid email format"),
        length(max = 320, message = "Email must be at most 320 characters")
    )]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 20, message = "Telephone number must be at most 20 characters"))]
    pub telephone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(length(max = 2048, message = "Password too long"))]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    #[validate(
        url(message = "Invalid URL format"),
        length(max = 2048, message = "URL must be at most 2048 characters")
    )]
    pub url: Option<String>,
}

/// Request payload for creating a new note.
#[derive(Debug, Deserialize, Serialize, validator::Validate, ToSchema)]
pub struct CreateNoteRequest {
    #[validate(
        required(message = "Title is required"),
        length(min = 1, max = 256, message = "Title must be 1-256 characters")
    )]
    pub title: Option<String>,
    #[validate(length(max = 25600, message = "Content must be at most 25600 characters"))]
    pub content: Option<String>,
}

/// Request payload for updating an existing note.
#[derive(Debug, Deserialize, Serialize, validator::Validate, ToSchema)]
pub struct UpdateNoteRequest {
    #[validate(length(min = 1, max = 256, message = "Title must be 1-256 characters"))]
    pub title: Option<String>,
    #[validate(length(max = 25600, message = "Content must be at most 25600 characters"))]
    pub content: Option<String>,
}

/// Response payload for a decrypted secret.
///
/// Params: Decrypted secret data.
/// Logic: Sensitive fields are decrypted only during request processing.
/// Returns: Secret response.
#[derive(Debug, Serialize, ToSchema)]
pub struct SecretResponse {
    pub id: SecretId,
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub telephone_number: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub url: Option<String>,
    pub is_favorite: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// Response payload for a decrypted note.
#[derive(Debug, Serialize, ToSchema)]
pub struct NoteResponse {
    pub id: NoteId,
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub content: Option<String>,
    pub is_favorite: bool,
    pub created_at: chrono::DateTime<chrono::Utc>,
    pub updated_at: chrono::DateTime<chrono::Utc>,
}

/// JWT claims structure.
///
/// Params: Standard JWT claims plus custom user_id.
/// Logic: Used for access token validation.
/// Returns: Token claims.
#[derive(Debug, Serialize, Deserialize)]
pub struct Claims {
    pub sub: String,
    pub user_id: Uuid,
    pub token_version: i32,
    pub exp: usize,
    pub iat: usize,
}

/// Generic API response wrapper.
///
/// Params: Success flag and optional message/data.
/// Logic: Standard response format for all endpoints.
/// Returns: API response.
#[derive(Debug, Serialize, ToSchema)]
pub struct ApiResponse<T> {
    pub success: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub message: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<T>,
}

impl<T> ApiResponse<T> {
    /// Creates a successful response with data.
    ///
    /// Params: Data to include in response.
    /// Logic: Sets success to true.
    /// Returns: Success response.
    #[must_use]
    pub fn success(data: T) -> Self {
        Self {
            success: true,
            message: None,
            data: Some(data),
        }
    }

    /// Creates a successful response with just a message.
    ///
    /// Params: Message string.
    /// Logic: Sets success to true with no data.
    /// Returns: Success response.
    #[must_use]
    pub fn message(msg: impl Into<String>) -> ApiResponse<()> {
        ApiResponse {
            success: true,
            message: Some(msg.into()),
            data: None,
        }
    }
}

// ----------------------------------------------------------------------------
// OpenAPI Schema Wrappers
// ----------------------------------------------------------------------------

#[derive(ToSchema)]
pub struct AuthResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    #[schema(example = "Login successful")]
    pub message: Option<String>,
    pub data: Option<AuthResponse>,
}

#[derive(ToSchema)]
pub struct SecretResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<SecretResponse>,
}

#[derive(ToSchema)]
pub struct SecretListResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<Vec<SecretResponse>>,
}

#[derive(ToSchema)]
pub struct NoteResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<NoteResponse>,
}

#[derive(ToSchema)]
pub struct NoteListResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<Vec<NoteResponse>>,
}

#[derive(ToSchema)]
pub struct EmptyResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    #[schema(example = "Operation successful")]
    pub message: Option<String>,
    #[schema(nullable = true)]
    pub data: Option<()>,
}

// ----------------------------------------------------------------------------
// BULK OPERATIONS
// ----------------------------------------------------------------------------

/// Request item for bulk create operations.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct BulkCreateItem {
    pub item_type: ItemType,
    pub data: serde_json::Value,
}

/// Request payload for bulk create items.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct BulkCreateRequest {
    #[validate(length(
        min = 1,
        max = 3000,
        message = "Items count must be between 1 and 3000"
    ))]
    pub items: Vec<BulkCreateItem>,
}

/// Response item for bulk create operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkCreateResultItem {
    pub id: Uuid,
    pub item_type: ItemType,
}

/// Response payload for bulk create operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkCreateResponse {
    pub created_count: usize,
    pub items: Vec<BulkCreateResultItem>,
}

/// Request item for bulk delete operations.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct BulkDeleteItem {
    pub id: Uuid,
    pub item_type: ItemType,
}

/// Request payload for bulk delete items.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct BulkDeleteRequest {
    #[validate(length(
        min = 1,
        max = 3000,
        message = "Items count must be between 1 and 3000"
    ))]
    pub items: Vec<BulkDeleteItem>,
}

/// Response payload for bulk delete operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkDeleteResponse {
    pub deleted_count: usize,
}

/// Request item for bulk favorite operations.
#[derive(Debug, Deserialize, Serialize, ToSchema)]
pub struct BulkFavoriteItem {
    pub id: Uuid,
    pub item_type: ItemType,
}

/// Request payload for bulk favorite/unfavorite.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct BulkFavoriteRequest {
    #[validate(length(
        min = 1,
        max = 3000,
        message = "Items count must be between 1 and 3000"
    ))]
    pub items: Vec<BulkFavoriteItem>,
}

/// Response payload for bulk favorite operations.
#[derive(Debug, Serialize, ToSchema)]
pub struct BulkFavoriteResponse {
    pub updated_count: usize,
}

// ----------------------------------------------------------------------------
// ACCOUNT MANAGEMENT
// ----------------------------------------------------------------------------

/// Request payload for initiating account deletion.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct DeleteAccountRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
}

/// Request payload for confirming account deletion with OTP.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct ConfirmDeleteAccountRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
    #[validate(length(equal = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
}

/// Request payload for initiating password change.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct ChangePasswordRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
}

/// Request payload for confirming password change with OTP.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct ConfirmChangePasswordRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
    #[validate(length(equal = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
    #[validate(
        length(
            min = 12,
            max = 256,
            message = "New password must be between 12 and 256 characters"
        ),
        custom(function = "validate_password_complexity")
    )]
    pub new_password: String,
}

/// Request payload for initiating email change.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct ChangeEmailRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
    #[validate(
        email(message = "Invalid email format"),
        length(max = 320, message = "Email must be at most 320 characters")
    )]
    pub new_email: String,
}

/// Request payload for confirming email change with OTP.
#[derive(Debug, Deserialize, validator::Validate, ToSchema)]
pub struct ConfirmChangeEmailRequest {
    #[validate(length(min = 1, max = 128, message = "Token must be 1-128 characters"))]
    pub refresh_token: String,
    #[validate(length(equal = 6, message = "OTP must be 6 digits"))]
    pub otp: String,
}

// ----------------------------------------------------------------------------
// OPENAPI WRAPPERS FOR NEW TYPES
// ----------------------------------------------------------------------------

#[derive(ToSchema)]
pub struct BulkCreateResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<BulkCreateResponse>,
}

#[derive(ToSchema)]
pub struct BulkDeleteResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<BulkDeleteResponse>,
}

#[derive(ToSchema)]
pub struct BulkFavoriteResponseWrapper {
    #[schema(example = true)]
    pub success: bool,
    pub message: Option<String>,
    pub data: Option<BulkFavoriteResponse>,
}
