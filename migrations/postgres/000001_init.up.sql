-- Auth domain: users, github/qrcode identities, devices, sessions.
-- Ported from the old WS project's schema, trimmed to what the auth
-- flow (GitHub OAuth + QR login + gRPC session resume) actually needs.
-- Profile/messenger-specific user columns (username, bio, message
-- privacy, bot flag, ...) are intentionally left out until those
-- domains are ported.

CREATE TABLE IF NOT EXISTS users (
    id             SERIAL PRIMARY KEY,
    email          VARCHAR(255) UNIQUE NOT NULL,
    full_name      VARCHAR(255),
    avatar_key     VARCHAR(255),
    created_at     TIMESTAMPTZ NOT NULL DEFAULT now(),
    deactivated_at TIMESTAMPTZ
);

CREATE TABLE IF NOT EXISTS auth_identities (
    id           BIGSERIAL PRIMARY KEY,
    user_id      INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    provider     VARCHAR(32) NOT NULL,
    identifier   VARCHAR(255) NOT NULL,
    created_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_used_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (provider, identifier)
);

CREATE TABLE IF NOT EXISTS user_devices (
    id            BIGSERIAL PRIMARY KEY,
    user_id       INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    fingerprint   VARCHAR(255) NOT NULL,
    device_name   VARCHAR(255),
    platform      VARCHAR(16),
    os            VARCHAR(64),
    first_seen_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    UNIQUE (user_id, fingerprint)
);

-- sessions.resume_secret_hash stores SHA-256(raw resume secret), base64
-- encoded. The raw secret is handed to the client exactly once (at
-- login / QR confirm) and never stored. Unlike the old WS project's
-- aes_key_b64, this is not a transport encryption key — wireauthgrpc
-- already secures every connection independently; this is purely a
-- resume credential proven over an already-secured channel.
CREATE TABLE IF NOT EXISTS sessions (
    auth_key_id        BIGINT PRIMARY KEY,
    user_id             INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    auth_identity_id    BIGINT REFERENCES auth_identities(id),
    device_id           BIGINT REFERENCES user_devices(id),
    ip_address           INET,
    user_agent           TEXT,
    resume_secret_hash   VARCHAR(128) NOT NULL,
    last_seen_seq        BIGINT NOT NULL DEFAULT 0,
    created_at           TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at       TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at           TIMESTAMPTZ,
    revoked_reason       VARCHAR(32)
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_users_email ON users(email);
CREATE INDEX IF NOT EXISTS idx_auth_identities_user ON auth_identities(user_id);
CREATE INDEX IF NOT EXISTS idx_sessions_user_active ON sessions(user_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_device ON sessions(device_id);