The Blueprint: Server-Side Zero-Knowledge Architecture
Core Philosophy: The Server is a blind processor. It possesses the strength (CPU) to decrypt and the memory (RAM) to hold data temporarily, but it relies entirely on the user to provide the "eyes" (the Key) for every single operation.

I. The Core Entities
Before the flow, we must define what exists in our persistence layers and memory.

The Master Key: Derived from the User's Password using Argon2. This is never stored on disk (DB) or cache (Redis). It exists only in the HTTP Request context and momentary RAM.

The Canary: A JSON object {"status": "verified"} encrypted with the Master Key. If this decrypts successfully, the user is valid.

The Secret: The actual user data (password, note), encrypted with the Master Key.

The Identity Card (Access Token): A short-lived (15 min) JWT signed by the server. It proves who the user is, but cannot decrypt data.

The Session Anchor (Refresh Token): A long-lived (30 days) opaque string hash. It allows the user to stay logged in without re-entering credentials, but it cannot decrypt data (only the user's memory can do that).

II. Phase 1: Registration (The Setup)
This is a one-time process to establish the "Canary" trap and the user identity.

Email Verification: User verifies email via magic link/OTP.

Key Generation (Client Side):

User inputs Master Password.

App generates a random Salt.

App sends Master Password + Salt to the API over TLS.

The Setup (Server Side - Blocking Task):

Server derives Master Key = Argon2id(Master Password, Salt).

Server creates the Canary Payload: {"msg": "OK"}.

Server Encrypts the Canary using the Master Key.

DB Action: Insert into Users table:

email

salt

encrypted_canary_blob

(Note: No password hash is stored.)

Cleanup: Server wipes the Master Key from memory immediately.

III. Phase 2: Login (The Exchange)
This occurs when the user first opens the app and enters their credentials to start a session.

The Trigger: POST /auth/login The Payload: email + master_password

The Server Logic:

Context Setup: Spawn tokio::task::spawn_blocking.

Canary Check (The Guard):

Fetch encrypted_canary_blob and salt from Postgres (or Redis if cached).

Derive Master Key using Argon2id(master_password, salt).

Attempt to decrypt the Canary blob.

If Decryption Fails: STOP. Return 401 Unauthorized.

Token Generation (Success):

Generate Access Token (JWT, 15 min expiration).

Generate Refresh Token (Random String, 30 days).

DB Action: Hash the Refresh Token (SHA256) and store it in refresh_tokens table.

Response: Return Access Token + Refresh Token to client.

Client State:

Store Refresh Token in Secure Storage (Keychain/Keystore).

Keep Master Password in Volatile RAM (Variable).

IV. Phase 3: The "Handshake" & Vault Access
This occurs every time the user views their secrets. The Client sends BOTH the Identity Card (JWT) and the Key (Master Password).

The Trigger: User requests GET /secrets. The Payload: Headers contain Authorization: Bearer <JWT> AND X-Master-Password (over HTTPS).

The Server Logic (Axum Middleware/Handler):

Layer 1: Identity Verification (Fast)

Axum Middleware: Verify JWT signature and expiration.

If Invalid: Return 401. (Stops DDoS attacks before heavy crypto starts).

If Valid: Extract user_id. Proceed to Layer 2.

Layer 2: Context Setup

Extract X-Master-Password.

Wrap it in secrecy::Secret<String> immediately.

Spawn a tokio::task::spawn_blocking thread (to not block the web server).

Layer 3: Canary Check (The Guard)

Why we do this again: To ensure the X-Master-Password provided in the header is actually correct before attempting to decrypt 100 secrets.

Redis Check: Look for user:{id}:canary.

Hit: Get the encrypted blob.

Miss: Fetch encrypted_canary_blob and salt from Postgres. Save to Redis (TTL 1 hour).

Derivation: Re-derive Master Key using Argon2id(Password, Salt).

Trial Decryption: Attempt to decrypt the Canary blob.

If Decryption Fails: STOP. Return 401.

If Decryption Succeeds: The Key is valid. Proceed to Layer 4.

Layer 4: Data Access (The Vault)

Cache/DB Fetch:

Redis Check: Look for user:{id}:secrets.

Hit: return Vec<EncryptedSecretBlob>.

Miss: Fetch all encrypted secrets for this user from Postgres.

Cache Warm-up: Store the Encrypted blobs in Redis (TTL 1 hour).

Note: We store Encrypted data in Redis. If Redis is hacked, they see garbage.

Bulk Decryption (Parallelized):

Since a user might have 50 passwords, we use Rayon inside the blocking task.

Iterate through the EncryptedSecretBlobs.

Decrypt each one using the Master Key (which we still have in memory from Layer 3).

Response:

Serialize the Decrypted (Plaintext) secrets to JSON.

Send response to Client.

The Wipe:

The Master Key goes out of scope.

secrecy crate automatically zeroes out the RAM where the key was stored.

Plaintext data is dropped from server memory.

V. Phase 4: Token Rotation (Session Continuity)
This occurs when the Access Token (15 min) expires, but the user is still using the app.

The Trigger: POST /auth/refresh The Payload: refresh_token (String).

The Server Logic:

Hash & Lookup: Compute SHA256(refresh_token). Check Redis blacklist:{hash} first. Then DB.

Security Check 1 (Reuse): Is this token already marked used?

Yes: Security Alert. Revoke the entire token family. Return 403.

Security Check 2 (Expiry): Is now > expires_at? Return 403.

Rotation:

Mark current token as used.

Generate NEW Access Token.

Generate NEW Refresh Token.

Save NEW hash to DB and Cache.

Response: Send new tokens.

Client Action:

Update Keychain.

Retry the original GET /secrets request using the New Token + Old Master Password (still in RAM).

VI. Phase 5: Writing Data (Adding a Password)
Request: User sends POST /secrets with body {"title": "Gmail", "password": "hunter2"}.

The Server Logic:

Identity: Verify JWT.

Encryption Access: Perform Phase 3, Layer 3 (Canary Check) to ensure the user provided the correct encryption key in the header.

Encryption:

Use the derived Master Key to encrypt the new data payload.

Result: EncryptedSecretBlob.

Persistence:

Save EncryptedSecretBlob to Postgres.

Invalidate Redis: Delete user:{id}:secrets key in Redis (forcing a fresh fetch next time).

VII. Summary of Security & Performance
This architecture achieves your goals perfectly:

Authentication: Verified by the "Canary". No hash is ever stored.

Session Security: Managed by JWT + Refresh Rotation. Stops replay attacks.

Redis Usage: Acts as a high-speed buffer for Encrypted data. It protects the Postgres DB from being hammered by requests.

Performance:

I/O: Handled by Tokio (Async).

Crypto: Handled by dedicated blocking threads (won't freeze the API).

Bulk Decryption: Handled by Rayon (Parallel processing of the list).

Attack Surface:

DB Leaked? Attackers see random bytes + SHA256 hashes. No keys, no passwords.

Redis Leaked? Attackers see random bytes + SHA256 hashes.

Server RAM Dumped? Attackers might find a key only if they dump RAM at the exact millisecond a request is being processed. (Acceptable risk for this scope).
