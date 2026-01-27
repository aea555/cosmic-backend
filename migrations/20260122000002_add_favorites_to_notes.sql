-- Add favorites column to notes table
-- Boolean column with default false is non-breaking for existing data

ALTER TABLE notes ADD COLUMN is_favorite BOOLEAN DEFAULT FALSE NOT NULL;

-- Index for efficiently filtering favorites by user
CREATE INDEX idx_notes_user_favorite ON notes(user_id, is_favorite);
