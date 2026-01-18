-- Create secrets table
-- All secret data is encrypted with the user's Master Key before storage.

CREATE TABLE secrets (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for fetching all secrets by user
CREATE INDEX idx_secrets_user_id ON secrets(user_id);
