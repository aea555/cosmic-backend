# Zero-Knowledge Password Manager API - Route Documentation

## Base URL
```
/api/v1
```

---

## Environment Variables Configuration

### Secure Configuration Methods

**1. Development (`.env` file)**
```bash
cp .env.example .env
# Edit .env with your values - NEVER commit this file
```

**2. Production (Environment injection)**
```bash
# Docker Compose (use docker secrets or environment)
docker compose --env-file .env.production up

# Kubernetes (use ConfigMaps/Secrets)
kubectl create secret generic cosmic-secrets \
  --from-literal=DATABASE_URL='postgres://...' \
  --from-literal=JWT_SECRET='...'

# Systemd service
Environment="DATABASE_URL=postgres://..."
```

**3. Secret Management Services**
- AWS Secrets Manager
- HashiCorp Vault  
- Doppler
- 1Password Secrets Automation

### Required Variables

| Variable | Description | Example |
|----------|-------------|---------|
| `DATABASE_URL` | PostgreSQL connection string | `postgres://user:pass@host:5432/db` |
| `REDIS_URL` | Valkey/Redis connection string | `redis://localhost:6379` |
| `JWT_SECRET` | JWT signing key (min 32 chars) | Random 64-char string |
| `APP_URL` | Application base URL | `https://api.app.org` |
| `EMAIL__MAILTRAP_API_TOKEN` | Mailtrap API token | `<token>` |
| `EMAIL__FROM_EMAIL` | Sender email address | `no-reply@clbio.org` |
| `EMAIL__FROM_NAME` | Sender display name | `APP_NAME` |
| `EMAIL__REPLY_TO_EMAIL` | Reply-to address | `support@app.org` |

### Optional Variables

| Variable | Default | Description |
|----------|---------|-------------|
| `JWT_EXPIRY_SECONDS` | `900` | Access token lifetime (15 min) |
| `REFRESH_TOKEN_EXPIRY_DAYS` | `30` | Refresh token lifetime |
| `SERVER_HOST` | `0.0.0.0` | Bind address |
| `SERVER_PORT` | `8080` | Listen port |

---

## Authentication Endpoints

### POST `/auth/register`
Creates a new user account and sends verification email.

**Request:**
```
Content-Type: application/json
```

**Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| `email` | string | ✅ | Valid email format |
| `password` | string | ✅ | Min 8 chars, 1 uppercase, 1 number |

**Response (201 Created):**
```json
{
  "success": true,
  "message": "Registration successful. Please check your email to verify your account.",
  "data": null
}
```

**Errors:**
| Code | Error | Description |
|------|-------|-------------|
| 400 | `VALIDATION_ERROR` | Invalid email/password format |
| 409 | `USER_EXISTS` | Email already registered |

---

### POST `/auth/verify-email`
Verifies email using token from email link.

**Request:**
```
Content-Type: application/json
```

**Body:**
```json
{
  "token": "abc123..."
}
```

| Field | Type | Required | Description |
|-------|------|----------|-------------|
| `token` | string | ✅ | Token from email link |

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Email verified successfully. You can now log in.",
  "data": null
}
```

**Errors:**
| Code | Error | Description |
|------|-------|-------------|
| 403 | `INVALID_VERIFICATION_TOKEN` | Token invalid or expired |

---

### POST `/auth/login`
Authenticates user and returns tokens.

**Request:**
```
Content-Type: application/json
```

**Body:**
```json
{
  "email": "user@example.com",
  "password": "SecurePassword123!"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": null,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "a1b2c3d4e5f6...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**Errors:**
| Code | Error | Description |
|------|-------|-------------|
| 401 | `INVALID_CREDENTIALS` | Wrong email or password |
| 403 | `EMAIL_NOT_VERIFIED` | Email not yet verified |

---

### POST `/auth/refresh`
Exchanges refresh token for new token pair.

**Request:**
```
Content-Type: application/json
```

**Body:**
```json
{
  "refresh_token": "a1b2c3d4e5f6..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbGciOiJIUzI1NiIs...",
    "refresh_token": "x9y8z7w6v5...",
    "token_type": "Bearer",
    "expires_in": 900
  }
}
```

**Errors:**
| Code | Error | Description |
|------|-------|-------------|
| 401 | `INVALID_TOKEN` | Token invalid or blacklisted |
| 403 | `TOKEN_REUSED` | Token already used (security breach) |
| 403 | `TOKEN_EXPIRED` | Token has expired |

---

### POST `/auth/logout`
Invalidates the refresh token.

**Request:**
```
Content-Type: application/json
```

**Body:**
```json
{
  "refresh_token": "a1b2c3d4e5f6..."
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Logged out successfully",
  "data": null
}
```

---

## Protected Endpoints (Secrets)

All endpoints require:
- `Authorization: Bearer <access_token>` header
- `X-Master-Password: <password>` header (for encryption/decryption)

### GET `/secrets`
Lists all decrypted secrets for the authenticated user.

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | ✅ | `Bearer <access_token>` |
| `X-Master-Password` | ✅ | User's master password |

**Response (200 OK):**
```json
{
  "success": true,
  "data": [
    {
      "id": "550e8400-e29b-41d4-a716-446655440000",
      "title": "Gmail",
      "username": "me@gmail.com",
      "password": "hunter2",
      "url": "https://gmail.com",
      "notes": "Personal email",
      "created_at": "2026-01-17T10:00:00Z",
      "updated_at": "2026-01-17T10:00:00Z"
    }
  ]
}
```

**Errors:**
| Code | Error | Description |
|------|-------|-------------|
| 401 | `INVALID_TOKEN` | JWT invalid or expired |
| 401 | `MASTER_PASSWORD_REQUIRED` | Missing X-Master-Password header |
| 401 | `INVALID_CREDENTIALS` | Wrong master password |

---

### GET `/secrets/:id`
Gets a single decrypted secret.

**Path Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `id` | UUID | Secret identifier |

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | ✅ | `Bearer <access_token>` |
| `X-Master-Password` | ✅ | User's master password |

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Gmail",
    "username": "me@gmail.com",
    "password": "hunter2",
    "url": "https://gmail.com",
    "notes": "Personal email",
    "created_at": "2026-01-17T10:00:00Z",
    "updated_at": "2026-01-17T10:00:00Z"
  }
}
```

**Errors:**
| Code | Error | Description |
|------|-------|-------------|
| 404 | `SECRET_NOT_FOUND` | Secret doesn't exist or not owned |

---

### POST `/secrets`
Creates a new encrypted secret.

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | ✅ | `Bearer <access_token>` |
| `X-Master-Password` | ✅ | User's master password |
| `Content-Type` | ✅ | `application/json` |

**Body:**
```json
{
  "title": "Gmail",
  "username": "me@gmail.com",
  "password": "hunter2",
  "url": "https://gmail.com",
  "notes": "Personal email"
}
```

| Field | Type | Required | Validation |
|-------|------|----------|------------|
| `title` | string | ✅ | Max 255 chars |
| `username` | string | ❌ | Max 255 chars |
| `password` | string | ❌ | Max 2048 chars |
| `url` | string | ❌ | Valid URL, max 2048 chars |
| `notes` | string | ❌ | Max 10000 chars |

**Response (201 Created):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Gmail",
    "username": "me@gmail.com",
    "password": "hunter2",
    "url": "https://gmail.com",
    "notes": "Personal email",
    "created_at": "2026-01-17T10:00:00Z",
    "updated_at": "2026-01-17T10:00:00Z"
  }
}
```

---

### PUT `/secrets/:id`
Updates an existing secret.

**Path Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `id` | UUID | Secret identifier |

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | ✅ | `Bearer <access_token>` |
| `X-Master-Password` | ✅ | User's master password |
| `Content-Type` | ✅ | `application/json` |

**Body:**
```json
{
  "title": "Gmail (Updated)",
  "username": "me@gmail.com",
  "password": "newpassword123",
  "url": "https://gmail.com",
  "notes": "Updated notes"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "data": {
    "id": "550e8400-e29b-41d4-a716-446655440000",
    "title": "Gmail (Updated)",
    ...
  }
}
```

---

### DELETE `/secrets/:id`
Deletes a secret.

**Path Parameters:**
| Param | Type | Description |
|-------|------|-------------|
| `id` | UUID | Secret identifier |

**Headers:**
| Header | Required | Description |
|--------|----------|-------------|
| `Authorization` | ✅ | `Bearer <access_token>` |

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Secret deleted successfully",
  "data": null
}
```

---

## Error Response Format

All errors follow this format:
```json
{
  "success": false,
  "error": "Human-readable message",
  "code": "ERROR_CODE"
}
```

## Rate Limiting

Rate limiting is implemented at the API layer using Redis-backed sliding window counters.

### Limits by Endpoint Type

| Endpoint Type | Limit | Window | Identifier |
|---------------|-------|--------|------------|
| `/auth/login`, `/auth/register` | **5 requests** | 60 sec | IP address |
| `/auth/verify-email`, `/auth/refresh`, `/auth/logout` | **10 requests** | 60 sec | IP address |
| `/secrets/*` (all CRUD) | **100 requests** | 60 sec | User ID |
| Global (all endpoints) | **200 requests** | 60 sec | IP address |

### Rate Limit Response (429 Too Many Requests)
```json
{
  "success": false,
  "error": "Rate limit exceeded. Retry after 60 seconds.",
  "code": "RATE_LIMITED"
}
```

### Headers
The `Retry-After` header indicates when the limit resets.

### Implementation Notes
- **IP Extraction**: Checks `X-Forwarded-For`, `X-Real-IP`, then falls back to peer address
- **Fail Open**: If Redis is unavailable, requests are allowed (graceful degradation)
- **Storage**: Keys are stored as `ratelimit:{prefix}:{identifier}` with TTL matching the window

## CORS

All origins allowed in development. Configure `CorsLayer` in `app.rs` for production.
