-- Add token_version to users table
ALTER TABLE users ADD COLUMN token_version INTEGER NOT NULL DEFAULT 0;
