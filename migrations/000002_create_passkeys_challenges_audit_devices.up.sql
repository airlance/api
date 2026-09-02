-- 000002_create_passkeys_challenges_audit_devices.up.sql

CREATE TABLE IF NOT EXISTS devices (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    device_identifier_hash BYTEA NOT NULL UNIQUE,
    platform TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_seen_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_app_version TEXT NULL,
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_devices_user_id ON devices(user_id);

ALTER TABLE sessions ADD COLUMN IF NOT EXISTS device_id UUID NULL REFERENCES devices(id) ON DELETE SET NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_device_id ON sessions(device_id);

CREATE TABLE IF NOT EXISTS passkey_credentials (
    id UUID PRIMARY KEY,
    identity_id UUID NOT NULL REFERENCES identities(id) ON DELETE CASCADE,
    credential_id BYTEA NOT NULL UNIQUE,
    public_key BYTEA NOT NULL,
    sign_count INTEGER NOT NULL DEFAULT 0,
    transports TEXT[] NOT NULL DEFAULT '{}',
    aaguid UUID NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    last_used_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_passkey_credentials_identity_id ON passkey_credentials(identity_id);

CREATE TABLE IF NOT EXISTS challenges (
    id UUID PRIMARY KEY,
    user_id UUID NULL REFERENCES users(id) ON DELETE CASCADE,
    type TEXT NOT NULL CHECK (type IN ('signup', 'registration', 'authentication')),
    session_data JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_challenges_expires_at ON challenges(expires_at);

CREATE TABLE IF NOT EXISTS audit_events (
    id UUID PRIMARY KEY,
    occurred_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    user_id UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    actor_type TEXT NOT NULL,
    actor_id UUID NULL,
    subject_type TEXT NULL,
    subject_hash BYTEA NULL,
    subject_hash_key_id SMALLINT NULL,
    event_type TEXT NOT NULL,
    ip TEXT NOT NULL,
    user_agent TEXT NOT NULL,
    request_id TEXT NOT NULL,
    metadata JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE INDEX IF NOT EXISTS idx_audit_events_user_id ON audit_events(user_id);
CREATE INDEX IF NOT EXISTS idx_audit_events_subject ON audit_events(subject_type, subject_hash);
CREATE INDEX IF NOT EXISTS idx_audit_events_occurred_at ON audit_events(occurred_at);
