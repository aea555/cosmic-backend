-- OTP requests table for sensitive operations
-- Used for: account deletion, password change, email change

CREATE TABLE otp_requests (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    otp_hash BYTEA NOT NULL,
    request_type VARCHAR(50) NOT NULL,
    new_email VARCHAR(255),
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ DEFAULT NOW() NOT NULL
);

-- Index for looking up OTP by user and type
CREATE INDEX idx_otp_user_type ON otp_requests(user_id, request_type);

-- Comment on request_type values
COMMENT ON COLUMN otp_requests.request_type IS 'Values: delete_account, change_password, change_email';
COMMENT ON COLUMN otp_requests.new_email IS 'Only populated for change_email requests';
