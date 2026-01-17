//! Cryptographic operations for the Zero-Knowledge architecture.
//!
//! This module implements all cryptographic primitives: key derivation (Argon2id),
//! symmetric encryption (ChaCha20-Poly1305), and hashing (SHA-256).
//! All operations use secrecy wrappers to ensure sensitive data is zeroed on drop.

use crate::error::{AppError, AppResult};
use crate::types::{EncryptedBlob, MasterKey, Salt};
use argon2::{Argon2, Params, password_hash::rand_core::OsRng};
use chacha20poly1305::{
    ChaCha20Poly1305, Nonce,
    aead::{Aead, KeyInit},
};
use rand::RngCore;
use sha2::{Digest, Sha256};

/// Nonce size for ChaCha20-Poly1305 (12 bytes).
const NONCE_SIZE: usize = 12;

/// Salt size for Argon2id (32 bytes).
const SALT_SIZE: usize = 32;

/// Canary payload that is encrypted and stored with each user.
/// If this decrypts successfully, the Master Password is valid.
const CANARY_PAYLOAD: &[u8] = b"{\"status\":\"verified\"}";

/// Generates a cryptographically secure random salt.
///
/// Params: None.
/// Logic: Uses OS random source for cryptographic strength.
/// Returns: A 32-byte random Salt.
pub fn generate_salt() -> Salt {
    let mut bytes = [0u8; SALT_SIZE];
    OsRng.fill_bytes(&mut bytes);
    Salt(bytes)
}

/// Generates a cryptographically secure random refresh token.
///
/// Params: None.
/// Logic: Generates 32 random bytes and encodes as base64-url-safe.
/// Returns: A 256-bit random token string.
#[must_use]
pub fn generate_refresh_token() -> String {
    let mut bytes = [0u8; 32];
    OsRng.fill_bytes(&mut bytes);
    base64_encode(&bytes)
}

/// Hashes a refresh token using SHA-256.
///
/// Params: Token string to hash.
/// Logic: Computes SHA-256 digest of the token bytes.
/// Returns: 32-byte hash as Vec.
#[must_use]
pub fn hash_refresh_token(token: &str) -> Vec<u8> {
    let mut hasher = Sha256::new();
    hasher.update(token.as_bytes());
    hasher.finalize().to_vec()
}

/// Hashes a verification token using SHA-256.
///
/// Params: Token string to hash.
/// Logic: Computes SHA-256 digest of the token bytes.
/// Returns: 32-byte hash as Vec.
#[must_use]
pub fn hash_verification_token(token: &str) -> Vec<u8> {
    hash_refresh_token(token)
}

/// Generates a cryptographically secure verification token.
///
/// Params: None.
/// Logic: Generates 32 random bytes and encodes as base64-url-safe.
/// Returns: A random token string suitable for email verification links.
#[must_use]
pub fn generate_verification_token() -> String {
    generate_refresh_token()
}

/// Derives a Master Key from a password and salt using Argon2id.
///
/// Params: Password string, Salt bytes.
/// Logic: Uses Argon2id with OWASP-recommended parameters for password hashing.
///        This is a CPU-intensive operation and should run in a blocking task.
/// Returns: A 32-byte MasterKey suitable for ChaCha20-Poly1305.
///
/// # Errors
/// Returns error if key derivation fails (should never happen with valid inputs).
pub fn derive_master_key(password: &str, salt: &Salt) -> AppResult<MasterKey> {
    // OWASP recommended parameters for Argon2id (2023)
    // Memory: 19 MiB, Iterations: 2, Parallelism: 1
    let params = Params::new(19 * 1024, 2, 1, Some(32))
        .map_err(|e| AppError::Crypto(format!("Failed to create Argon2 params: {}", e)))?;

    let argon2 = Argon2::new(argon2::Algorithm::Argon2id, argon2::Version::V0x13, params);

    let mut key = [0u8; 32];
    argon2
        .hash_password_into(password.as_bytes(), salt.as_bytes(), &mut key)
        .map_err(|e| AppError::Crypto(format!("Key derivation failed: {}", e)))?;

    Ok(MasterKey::new(key))
}

/// Encrypts plaintext using ChaCha20-Poly1305.
///
/// Params: Plaintext bytes, MasterKey.
/// Logic: Generates random nonce, encrypts data, prepends nonce to ciphertext.
/// Returns: EncryptedBlob containing nonce + ciphertext.
///
/// # Errors
/// Returns error if encryption fails.
pub fn encrypt(plaintext: &[u8], key: &MasterKey) -> AppResult<EncryptedBlob> {
    let cipher = ChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|e| AppError::Crypto(format!("Failed to create cipher: {}", e)))?;

    let mut nonce_bytes = [0u8; NONCE_SIZE];
    OsRng.fill_bytes(&mut nonce_bytes);
    let nonce = Nonce::from_slice(&nonce_bytes);

    let ciphertext = cipher
        .encrypt(nonce, plaintext)
        .map_err(|e| AppError::Crypto(format!("Encryption failed: {}", e)))?;

    // Prepend nonce to ciphertext
    let mut result = Vec::with_capacity(NONCE_SIZE + ciphertext.len());
    result.extend_from_slice(&nonce_bytes);
    result.extend_from_slice(&ciphertext);

    Ok(EncryptedBlob::new(result))
}

/// Decrypts ciphertext using ChaCha20-Poly1305.
///
/// Params: EncryptedBlob containing nonce + ciphertext, MasterKey.
/// Logic: Extracts nonce from first 12 bytes, decrypts remaining data.
/// Returns: Decrypted plaintext bytes.
///
/// # Errors
/// Returns error if decryption fails (wrong key or corrupted data).
pub fn decrypt(encrypted: &EncryptedBlob, key: &MasterKey) -> AppResult<Vec<u8>> {
    let data = encrypted.as_bytes();

    if data.len() < NONCE_SIZE {
        return Err(AppError::Crypto("Ciphertext too short".to_string()));
    }

    let (nonce_bytes, ciphertext) = data.split_at(NONCE_SIZE);
    let nonce = Nonce::from_slice(nonce_bytes);

    let cipher = ChaCha20Poly1305::new_from_slice(key.expose())
        .map_err(|e| AppError::Crypto(format!("Failed to create cipher: {}", e)))?;

    cipher
        .decrypt(nonce, ciphertext)
        .map_err(|_| AppError::InvalidCredentials)
}

/// Creates an encrypted Canary using the Master Key.
///
/// Params: MasterKey derived from user's password.
/// Logic: Encrypts the standard canary payload. Used during registration.
/// Returns: EncryptedBlob containing the encrypted canary.
///
/// # Errors
/// Returns error if encryption fails.
pub fn create_canary(key: &MasterKey) -> AppResult<EncryptedBlob> {
    encrypt(CANARY_PAYLOAD, key)
}

/// Verifies the Master Key by attempting to decrypt the Canary.
///
/// Params: Encrypted canary blob, MasterKey to verify.
/// Logic: Attempts decryption. If successful and payload matches, key is valid.
/// Returns: True if key is valid, false otherwise.
pub fn verify_canary(encrypted_canary: &EncryptedBlob, key: &MasterKey) -> bool {
    match decrypt(encrypted_canary, key) {
        Ok(plaintext) => plaintext == CANARY_PAYLOAD,
        Err(_) => false,
    }
}

/// Encodes bytes as URL-safe base64 without padding.
///
/// Params: Bytes to encode.
/// Logic: Standard base64url encoding.
/// Returns: Encoded string.
fn base64_encode(bytes: &[u8]) -> String {
    use base64::prelude::*;
    BASE64_URL_SAFE_NO_PAD.encode(bytes)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_key_derivation_consistency() {
        let password = "test_password_123";
        let salt = generate_salt();

        let key1 = derive_master_key(password, &salt).expect("Key derivation failed");
        let key2 = derive_master_key(password, &salt).expect("Key derivation failed");

        assert_eq!(key1.expose(), key2.expose());
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let password = "test_password_123";
        let salt = generate_salt();
        let key = derive_master_key(password, &salt).expect("Key derivation failed");

        let plaintext = b"Hello, Zero-Knowledge World!";
        let encrypted = encrypt(plaintext, &key).expect("Encryption failed");
        let decrypted = decrypt(&encrypted, &key).expect("Decryption failed");

        assert_eq!(plaintext.as_slice(), decrypted.as_slice());
    }

    #[test]
    fn test_wrong_key_fails_decryption() {
        let salt = generate_salt();
        let key1 = derive_master_key("password1", &salt).expect("Key derivation failed");
        let key2 = derive_master_key("password2", &salt).expect("Key derivation failed");

        let plaintext = b"Secret data";
        let encrypted = encrypt(plaintext, &key1).expect("Encryption failed");

        assert!(decrypt(&encrypted, &key2).is_err());
    }

    #[test]
    fn test_canary_verification() {
        let salt = generate_salt();
        let key = derive_master_key("my_master_password", &salt).expect("Key derivation failed");

        let canary = create_canary(&key).expect("Canary creation failed");

        assert!(verify_canary(&canary, &key));

        let wrong_key = derive_master_key("wrong_password", &salt).expect("Key derivation failed");
        assert!(!verify_canary(&canary, &wrong_key));
    }

    #[test]
    fn test_refresh_token_generation() {
        let token1 = generate_refresh_token();
        let token2 = generate_refresh_token();

        assert_ne!(token1, token2);
        assert!(!token1.is_empty());
    }

    #[test]
    fn test_token_hashing() {
        let token = "test_token_12345";
        let hash1 = hash_refresh_token(token);
        let hash2 = hash_refresh_token(token);

        assert_eq!(hash1, hash2);
        assert_eq!(hash1.len(), 32);
    }
}
