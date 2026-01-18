-- Create notes table
-- Secure notes are encrypted with the user's Master Key before storage.

CREATE TABLE notes (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data BYTEA NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL,
    updated_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for fetching all notes by user
CREATE INDEX idx_notes_user_id ON notes(user_id);
