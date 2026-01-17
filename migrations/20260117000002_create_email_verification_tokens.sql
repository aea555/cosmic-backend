-- Create email verification tokens table
-- Used for email verification during registration.

CREATE TABLE email_verification_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_hash BYTEA NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for token hash lookups
CREATE INDEX idx_email_verification_tokens_hash ON email_verification_tokens(token_hash);

-- Index for user_id to find tokens by user
CREATE INDEX idx_email_verification_tokens_user_id ON email_verification_tokens(user_id);
