-- Create refresh tokens table
-- Tokens are hashed with SHA-256 before storage for security.
-- The 'used' flag enables rotation detection (token reuse = potential attack).

CREATE TABLE refresh_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA UNIQUE NOT NULL,
    used BOOLEAN DEFAULT FALSE NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for user_id to find all tokens for a user (for family revocation)
CREATE INDEX idx_refresh_tokens_user_id ON refresh_tokens(user_id);

-- Index for token hash lookups during validation
CREATE INDEX idx_refresh_tokens_hash ON refresh_tokens(token_hash);
