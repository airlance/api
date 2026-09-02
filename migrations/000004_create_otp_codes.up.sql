-- 000004_create_otp_codes.up.sql

CREATE TABLE IF NOT EXISTS otp_codes (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    email TEXT NOT NULL,
    purpose TEXT NOT NULL CHECK (purpose IN ('link_email')),
    code_hash BYTEA NOT NULL,
    key_id SMALLINT NOT NULL,
    attempts INT NOT NULL DEFAULT 0,
    max_attempts INT NOT NULL DEFAULT 5,
    expires_at TIMESTAMPTZ NOT NULL,
    consumed_at TIMESTAMPTZ NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_otp_codes_email_purpose_active
    ON otp_codes(email, purpose) WHERE consumed_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_otp_codes_expires_at ON otp_codes(expires_at);
