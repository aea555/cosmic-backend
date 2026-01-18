# Cosmic Vault API Guide for React Native Developer Agent

This document provides everything needed to integrate a React Native app with the Cosmic Vault backend API.

## Table of Contents
1. [Architecture Overview](#architecture-overview)
2. [Base URL & Headers](#base-url--headers)
3. [Authentication Flow](#authentication-flow)
4. [Deep Linking (Email Verification)](#deep-linking-email-verification)
5. [API Endpoints](#api-endpoints)
6. [Error Handling](#error-handling)
7. [Security Requirements](#security-requirements)

---

## Architecture Overview

Cosmic Vault is a **Zero-Knowledge Password Manager**. This means:
- The server **never sees plaintext passwords or secrets**
- All encryption/decryption happens **client-side**
- The `Master Password` is used to derive an encryption key (never sent to server)
- The `X-Master-Password` header is required for secrets/notes operations

---

## Base URL & Headers

### Base URL
```
Production: https://your-domain.com
Development: http://localhost:9090
```

### Required Headers

| Header | Required For | Description |
|--------|--------------|-------------|
| `Content-Type` | All POST/PUT | `application/json` |
| `Authorization` | Protected routes | `Bearer <access_token>` |
| `X-Master-Password` | Secrets/Notes | User's master password (plaintext) |

---

## Authentication Flow

### 1. Registration
```
POST /api/v1/auth/register
```
**Request:**
```json
{
  "email": "user@example.com",
  "password": "masterpassword123"
}
```
**Response (201):**
```json
{
  "success": true,
  "message": "Registration successful. Please check your email to verify your account."
}
```

### 2. Email Verification (via Deep Link)
User clicks link in email → App opens → Extract token → Call API:
```
POST /api/v1/auth/verify-email
```
**Request:**
```json
{
  "token": "abc123..."
}
```
**Response (200):**
```json
{
  "success": true,
  "message": "Email verified successfully. You can now log in."
}
```

### 2b. Resend Verification Email
If the user didn't receive the email or the token expired (24 hours):
```
POST /api/v1/auth/resend-verification
```
**Request:**
```json
{
  "email": "user@example.com"
}
```
**Response (200):**
```json
{
  "success": true,
  "message": "Verification email sent. Please check your inbox."
}
```
**Error Responses:**
- `409 EMAIL_ALREADY_VERIFIED` - User is already verified
- `429 VERIFICATION_PENDING` - Must wait before resending (includes `retry_after` seconds)

### 3. Login
```
POST /api/v1/auth/login
```
**Request:**
```json
{
  "email": "user@example.com",
  "password": "masterpassword123"
}
```
**Response (200):**
```json
{
  "success": true,
  "data": {
    "access_token": "eyJhbG...",
    "refresh_token": "a1b2c3...",
    "expires_in": 900
  }
}
```

### 4. Token Refresh
```
POST /api/v1/auth/refresh
```
**Request:**
```json
{
  "refresh_token": "a1b2c3..."
}
```
**Response (200):** Same as login

### 5. Logout
```
POST /api/v1/auth/logout
```
**Request:**
```json
{
  "refresh_token": "a1b2c3..."
}
```
**Response (200):**
```json
{
  "success": true,
  "message": "Logged out successfully"
}
```

---

## Deep Linking (Email Verification)

### App Configuration

**app.json (Expo):**
```json
{
  "expo": {
    "scheme": "cosmicvault"
  }
}
```

### Handling Deep Links

```javascript
import { useEffect } from 'react';
import { Linking } from 'react-native';

function App() {
  useEffect(() => {
    // Handle deep link when app opens
    Linking.getInitialURL().then(url => {
      if (url) handleDeepLink(url);
    });

    // Handle deep link when app is already open
    const subscription = Linking.addEventListener('url', ({ url }) => {
      handleDeepLink(url);
    });

    return () => subscription.remove();
  }, []);
}

async function handleDeepLink(url) {
  // url format: "cosmicvault://verify-email?token=abc123"
  try {
    const urlObj = new URL(url);
    
    if (urlObj.pathname === 'verify-email' || url.includes('verify-email')) {
      const token = urlObj.searchParams.get('token');
      
      if (token) {
        const response = await fetch(`${API_BASE_URL}/api/v1/auth/verify-email`, {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify({ token }),
        });
        
        const data = await response.json();
        
        if (data.success) {
          // Show success, navigate to login
          Alert.alert('Success', 'Email verified! You can now log in.');
        } else {
          Alert.alert('Error', data.error || 'Verification failed');
        }
      }
    }
  } catch (error) {
    console.error('Deep link error:', error);
  }
}
```

### Resend Verification Implementation

```javascript
import { useState } from 'react';

function ResendVerification({ email }) {
  const [isLoading, setIsLoading] = useState(false);
  const [cooldown, setCooldown] = useState(0);
  const [message, setMessage] = useState('');

  // Countdown timer for cooldown
  useEffect(() => {
    if (cooldown > 0) {
      const timer = setTimeout(() => setCooldown(cooldown - 1), 1000);
      return () => clearTimeout(timer);
    }
  }, [cooldown]);

  async function handleResend() {
    if (cooldown > 0 || isLoading) return;
    
    setIsLoading(true);
    setMessage('');
    
    try {
      const response = await fetch(`${API_BASE_URL}/api/v1/auth/resend-verification`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email }),
      });
      
      const data = await response.json();
      
      if (response.ok) {
        setMessage('Verification email sent!');
        setCooldown(60); // Prevent spam clicking
      } else if (data.code === 'VERIFICATION_PENDING') {
        // Extract retry_after from error message or set default
        const match = data.error.match(/(\d+) seconds/);
        const seconds = match ? parseInt(match[1]) : 60;
        setCooldown(seconds);
        setMessage(`Please wait ${seconds}s before resending`);
      } else if (data.code === 'EMAIL_ALREADY_VERIFIED') {
        setMessage('Email is already verified. You can log in.');
      } else {
        setMessage(data.error || 'Failed to resend');
      }
    } catch (error) {
      setMessage('Network error. Please try again.');
    } finally {
      setIsLoading(false);
    }
  }

  return (
    <View>
      <Button
        title={cooldown > 0 ? `Resend in ${cooldown}s` : 'Resend Verification Email'}
        onPress={handleResend}
        disabled={cooldown > 0 || isLoading}
      />
      {message && <Text>{message}</Text>}
    </View>
  );
}
```

---

## API Endpoints

### Health Check
```
GET /api/v1/health
```
**Response (200):** Empty body (just status 200)

---

### Secrets

All secrets endpoints require:
- `Authorization: Bearer <token>`
- `X-Master-Password: <master_password>`

#### List All Secrets
```
GET /api/v1/secrets
```
**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "title": "My Website",
      "username": "john",
      "email": "john@example.com",
      "password": "decrypted_password",
      "url": "https://example.com",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### Get Single Secret
```
GET /api/v1/secrets/{id}
```

#### Create Secret
```
POST /api/v1/secrets
```
**Request:**
```json
{
  "title": "My Website",
  "username": "john",
  "email": "john@example.com",
  "password": "secret123",
  "url": "https://example.com",
  "telephone_number": "+1234567890"
}
```
**Note:** Only `title` is required. All other fields are optional.

#### Update Secret
```
PUT /api/v1/secrets/{id}
```
**Request:** Same as create

#### Delete Secret
```
DELETE /api/v1/secrets/{id}
```

---

### Notes

Same authorization requirements as Secrets.

#### List All Notes
```
GET /api/v1/notes
```
**Response (200):**
```json
{
  "success": true,
  "data": [
    {
      "id": "uuid",
      "title": "My Note",
      "content": "Note content here...",
      "created_at": "2024-01-01T00:00:00Z",
      "updated_at": "2024-01-01T00:00:00Z"
    }
  ]
}
```

#### Get Single Note
```
GET /api/v1/notes/{id}
```

#### Create Note
```
POST /api/v1/notes
```
**Request:**
```json
{
  "title": "My Note",
  "content": "Note content here..."
}
```
**Note:** `title` is required, `content` is optional.

#### Update Note
```
PUT /api/v1/notes/{id}
```

#### Delete Note
```
DELETE /api/v1/notes/{id}
```

---

## Error Handling

### Error Response Format
```json
{
  "success": false,
  "error": "User-friendly error message",
  "code": "ERROR_CODE"
}
```

### Error Codes Reference

| HTTP | Code | Meaning | User-Friendly Message |
|------|------|---------|----------------------|
| 400 | `VALIDATION_ERROR` | Invalid input | "Please check your input and try again" |
| 401 | `INVALID_CREDENTIALS` | Wrong email/password | "Invalid email or password" |
| 401 | `INVALID_TOKEN` | JWT expired/invalid | "Session expired. Please log in again" |
| 401 | `MASTER_PASSWORD_REQUIRED` | Missing header | "Master password is required" |
| 403 | `TOKEN_REUSED` | Refresh token reused | "Security alert: Please log in again" |
| 403 | `TOKEN_EXPIRED` | Token expired | "Session expired. Please log in again" |
| 403 | `EMAIL_NOT_VERIFIED` | Unverified email | "Please verify your email first" |
| 403 | `INVALID_VERIFICATION_TOKEN` | Bad verify token | "Verification link is invalid or expired" |
| 404 | `USER_NOT_FOUND` | User doesn't exist | "Account not found" |
| 404 | `SECRET_NOT_FOUND` | Secret doesn't exist | "Item not found" |
| 409 | `USER_EXISTS` | Duplicate email | "An account with this email already exists" |
| 409 | `EMAIL_ALREADY_VERIFIED` | Already verified | "This email is already verified" |
| 422 | `INVALID_REQUEST_BODY` | Malformed JSON | "Invalid request format" |
| 429 | `RATE_LIMITED` | Too many requests | "Too many attempts. Please wait a moment" |
| 429 | `VERIFICATION_PENDING` | Token still valid | "Please wait X seconds before resending" |
| 500 | `INTERNAL_ERROR` | Server error | "Something went wrong. Please try again later" |

### Recommended Error Handler

```javascript
async function apiRequest(endpoint, options = {}) {
  try {
    const response = await fetch(`${API_BASE_URL}${endpoint}`, {
      ...options,
      headers: {
        'Content-Type': 'application/json',
        ...options.headers,
      },
    });

    const data = await response.json();

    if (!response.ok) {
      // Map to user-friendly messages
      const friendlyMessages = {
        'INVALID_CREDENTIALS': 'Invalid email or password',
        'INVALID_TOKEN': 'Session expired. Please log in again',
        'MASTER_PASSWORD_REQUIRED': 'Master password is required',
        'EMAIL_NOT_VERIFIED': 'Please verify your email first',
        'RATE_LIMITED': 'Too many attempts. Please wait a moment',
        'USER_EXISTS': 'An account with this email already exists',
        'SECRET_NOT_FOUND': 'Item not found',
        'VALIDATION_ERROR': data.error || 'Please check your input',
      };

      const message = friendlyMessages[data.code] || 'Something went wrong. Please try again.';
      throw new Error(message);
    }

    return data;
  } catch (error) {
    if (error.message.includes('Network')) {
      throw new Error('No internet connection. Please check your network.');
    }
    throw error;
  }
}
```

---

## Security Requirements

### Token Storage
- Store `access_token` in memory (not AsyncStorage)
- Store `refresh_token` in secure storage (react-native-keychain)
- Never log tokens

### Master Password Handling
- **Never store** the master password
- Prompt user each session
- Send in `X-Master-Password` header for vault operations
- Clear from memory when app backgrounds

### Rate Limits
| Endpoint Type | Limit |
|--------------|-------|
| Login/Register | 5/minute |
| Verify/Refresh/Logout | 10/minute |
| Protected routes | 100/minute per user |

### Password Requirements
The backend enforces the following validation rules for the Master Password:
- **Minimum Length:** 12 characters
- **Maximum Length:** 256 characters
- **Complexity:**
  - At least 1 Uppercase Letter
  - At least 1 Lowercase Letter
  - At least 1 Number
  - At least 1 Special Character (non-alphanumeric)

### Input Constraints
- **Global Payload Size:** 1MB max (JSON body)
- **Email Address:** Max 320 characters
- **Auth Tokens:** Max 128 characters
- **Secrets/Notes:** Encrypted blobs have higher limits, but titles/metadata are strictly bounded.

---

## Quick Reference

### Auth Endpoints (No JWT required)
| Method | Endpoint | Rate Limit |
|--------|----------|------------|
| POST | `/api/v1/auth/register` | 5/min |
| POST | `/api/v1/auth/login` | 5/min |
| POST | `/api/v1/auth/verify-email` | 10/min |
| POST | `/api/v1/auth/resend-verification` | 10/min |
| POST | `/api/v1/auth/refresh` | 10/min |
| POST | `/api/v1/auth/logout` | 10/min |

### Protected Endpoints (JWT + Master Password)
| Method | Endpoint | Description |
|--------|----------|-------------|
| GET | `/api/v1/secrets` | List all secrets |
| POST | `/api/v1/secrets` | Create secret |
| GET | `/api/v1/secrets/{id}` | Get secret |
| PUT | `/api/v1/secrets/{id}` | Update secret |
| DELETE | `/api/v1/secrets/{id}` | Delete secret |
| GET | `/api/v1/notes` | List all notes |
| POST | `/api/v1/notes` | Create note |
| GET | `/api/v1/notes/{id}` | Get note |
| PUT | `/api/v1/notes/{id}` | Update note |
| DELETE | `/api/v1/notes/{id}` | Delete note |
