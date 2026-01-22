-- Add favorites column to secrets table
-- Boolean column with default false is non-breaking for existing data

ALTER TABLE secrets ADD COLUMN is_favorite BOOLEAN DEFAULT FALSE NOT NULL;

-- Index for efficiently filtering favorites by user
CREATE INDEX idx_secrets_user_favorite ON secrets(user_id, is_favorite);
