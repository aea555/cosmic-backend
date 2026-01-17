-- Create users table
-- No password hash is stored per Zero-Knowledge architecture.
-- The encrypted_canary is used to verify the master password.

CREATE TABLE users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    email VARCHAR(255) UNIQUE NOT NULL,
    salt BYTEA NOT NULL,
    encrypted_canary BYTEA NOT NULL,
    email_verified BOOLEAN DEFAULT FALSE NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for email lookups during login
CREATE INDEX idx_users_email ON users(email);
