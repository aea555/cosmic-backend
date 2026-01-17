# Cosmic Vault Backend

A zero-knowledge password manager API that keeps your secrets truly secret.

---

## 📖 Introduction

Cosmic Vault is a password manager built on a simple but powerful principle: **the server never stores your password**.

Unlike traditional password managers that store password hashes, Cosmic Vault implements a **zero-knowledge architecture**. Your Master Password is used to derive an encryption key on the server, but the password itself is never stored—not even as a hash. The server encrypts and decrypts data in-memory, then immediately discards the key.

### What It Does

- **Securely stores passwords and notes** — All data is encrypted server-side using your Master Password
- **User authentication** — Email-verified accounts with JWT-based session management
- **Cross-platform sync** — Access your vault from any device with the mobile app
- **Zero-knowledge proof** — Server verifies your password without storing a hash

When you enter your Master Password:
1. Server derives an encryption key using Argon2id (password + stored salt)
2. Server encrypts a known "canary" phrase with that key
3. If the result matches what was stored during registration, password is correct

The magic: **no password hash exists anywhere**. An attacker with database access sees only encrypted blobs and random salts—useless without the password to re-derive the key.

---

## 🛠 Tech Stack

### Core Framework
| Crate | Purpose |
|-------|---------|
| `tokio` | Async runtime with full features |
| `axum` | Modern, ergonomic web framework |
| `tower` | Middleware and service utilities |
| `tower-http` | HTTP-specific middleware (CORS, tracing, compression) |

### Database & Cache
| Crate | Purpose |
|-------|---------|
| `sqlx` | Compile-time checked async SQL with PostgreSQL |
| `redis` / `deadpool-redis` | Redis/Valkey connection pooling for caching |

### Cryptography
| Crate | Purpose |
|-------|---------|
| `argon2` | Memory-hard key derivation (Argon2id) |
| `chacha20poly1305` | Authenticated encryption (ChaCha20-Poly1305) |
| `sha2` | SHA-256 for token hashing |
| `rand` | Cryptographically secure random number generation |
| `secrecy` | Memory-safe secret handling with auto-zeroing |

### Authentication & Security
| Crate | Purpose |
|-------|---------|
| `jsonwebtoken` | JWT encoding/decoding for access tokens |
| `validator` | Request payload validation with derive macros |

### Observability & Documentation
| Crate | Purpose |
|-------|---------|
| `tracing` / `tracing-subscriber` | Structured logging with environment filtering |
| `utoipa` / `utoipa-scalar` | OpenAPI spec generation with Scalar UI |

### Utilities
| Crate | Purpose |
|-------|---------|
| `serde` / `serde_json` | Serialization/deserialization |
| `thiserror` | Ergonomic error type definitions |
| `rayon` | Parallel iteration for bulk decryption |
| `reqwest` | HTTP client for Mailtrap email API |
| `chrono` | Date/time handling |
| `uuid` | UUID v4 generation |

---

## ⚙️ Core Business Logic

### The Zero-Knowledge Flow

#### Registration
```
1. User submits email + master password
2. Server generates random 32-byte salt
3. Server derives key: Argon2id(password, salt) → 256-bit key
4. Server encrypts canary: ChaCha20-Poly1305(key, "cosmic-canary-v1")
5. Server stores: { email, salt, encrypted_canary }
6. Key is discarded from memory
```

**Note:** No password hash stored. Only salt + encrypted canary (useless without password).

#### Authentication (Login)
```
1. User submits email + master password
2. Server looks up user → returns salt + encrypted_canary

   [Server-side re-derivation]
3. Derive key: Argon2id(password, salt) → 256-bit key
4. Encrypt canary with derived key
5. Compare: new_encrypted == stored_encrypted?
   - Match: Password correct (without knowing it)
   - Mismatch: Wrong password
6. Issue JWT access token + refresh token
```

#### Vault Operations
```
Every request to /secrets or /notes includes:
- Authorization: Bearer <jwt>
- X-Master-Password: <master_password>

Server flow:
1. Validate JWT → extract user_id
2. Derive key from X-Master-Password + user's salt
3. Verify canary (proves correct password)
4. For reads: Decrypt stored blobs → return plaintext
5. For writes: Encrypt plaintext → store blob
```

### Token Security

| Token Type | Storage | Lifetime | Security |
|------------|---------|----------|----------|
| Access Token | Memory only | 15 minutes | JWT, signed with HS256 |
| Refresh Token | Secure storage | 30 days | UUID, SHA-256 hashed in DB |

**Refresh Token Rotation:** Each refresh issues new tokens and invalidates the old one. Reuse of an old refresh token triggers a security alert.

### Caching Strategy

- **Read-through cache:** Check Redis first, fallback to Postgres
- **Cache keys:** `user:{id}:secrets`, `secret:{id}`
- **TTL:** 1 hour
- **Invalidation:** On every write (create, update, delete)

---

## 🏗 Architecture

### Layer Structure

```
┌─────────────────────────────────────────────────────────┐
│                     HTTP Layer                          │
│  (axum routes, middleware, request/response handling)   │
├─────────────────────────────────────────────────────────┤
│                   Handler Layer                         │
│  (thin controllers, validation, response formatting)    │
├─────────────────────────────────────────────────────────┤
│                    Core Layer                           │
│  (business logic: auth, vault, crypto operations)       │
├─────────────────────────────────────────────────────────┤
│                 Repository Layer                        │
│  (database queries, data access objects)                │
├─────────────────────────────────────────────────────────┤
│              Infrastructure Layer                       │
│  (PostgreSQL, Redis/Valkey, Email Service)              │
└─────────────────────────────────────────────────────────┘
```

### Module Breakdown

| Module | Responsibility |
|--------|----------------|
| `app.rs` | Application bootstrapping, database connections, middleware stack |
| `routes/` | Route definitions, middleware attachment, endpoint grouping |
| `handlers/` | HTTP handlers, request validation, response building |
| `core/auth.rs` | Registration, login, token management, canary verification |
| `core/vault.rs` | Secret/note encryption, decryption, CRUD orchestration |
| `core/crypto.rs` | Key derivation (Argon2id), encryption (ChaCha20-Poly1305) |
| `repository/` | Database queries using sqlx, typed data access |
| `cache/` | Redis operations, caching logic, invalidation |
| `middleware/` | JWT auth, rate limiting, IP extraction |
| `types/` | Newtype wrappers, request/response DTOs, domain models |
| `error.rs` | Centralized error types, HTTP response mapping |
| `config/` | Environment-based configuration loading |

### Request Flow Example

```
POST /api/v1/secrets
        │
        ▼
┌─────────────────┐
│  Rate Limiter   │ → Check Redis: user:{id} request count
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  JWT Middleware │ → Validate token, extract user_id
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│    Handler      │ → Validate body, extract X-Master-Password
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Core: Auth    │ → Derive key, verify canary
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│  Core: Vault    │ → Encrypt secret with ChaCha20-Poly1305
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│   Repository    │ → INSERT encrypted blob into Postgres
└────────┬────────┘
         │
         ▼
┌─────────────────┐
│     Cache       │ → Invalidate user's secrets cache
└────────┬────────┘
         │
         ▼
      Response: 201 Created
```

---

## ✨ Highlights

### Security Implementation
- Zero-knowledge authentication without storing password hashes
- Memory-safe secret handling with automatic zeroing (secrecy crate)
- Argon2id key derivation resistant to GPU/ASIC attacks
- ChaCha20-Poly1305 authenticated encryption
- Refresh token rotation with reuse detection
- Rate limiting per IP and per user

### Rust Best Practices
- Newtype pattern for type-safe IDs (UserId, SecretId, NoteId)
- Comprehensive error handling with thiserror
- Async/await throughout with Tokio
- Compile-time SQL verification with sqlx
- Parallel decryption using Rayon for bulk operations

### API Design
- RESTful endpoints with consistent response format
- OpenAPI documentation with Scalar UI
- Environment-aware CORS (strict in production)
- Deep link support for mobile email verification
- User-friendly error messages (no internal details leaked)

### Infrastructure
- Docker-ready with multi-stage builds
- PostgreSQL for persistence, Redis/Valkey for caching
- Health checks for container orchestration
- Environment-based configuration with sensible defaults
