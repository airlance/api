CREATE TABLE IF NOT EXISTS accounts (
    id          BIGSERIAL PRIMARY KEY,
    email       TEXT NOT NULL UNIQUE,
    first_name  TEXT NOT NULL,
    last_name   TEXT NOT NULL,
    session_ttl_months SMALLINT CHECK (session_ttl_months IS NULL OR session_ttl_months IN (3, 6, 12)),
    confirmed   BOOLEAN NOT NULL DEFAULT FALSE,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS email_confirmation_codes (
    account_id  BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    code_hash   BYTEA NOT NULL,
    expires_at  TIMESTAMPTZ NOT NULL,
    attempts    INT NOT NULL DEFAULT 0,
    PRIMARY KEY (account_id)
);

CREATE TABLE IF NOT EXISTS devices (
    id          BIGSERIAL PRIMARY KEY,
    account_id  BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    public_key  BYTEA NOT NULL UNIQUE,
    fingerprint    TEXT,
    device_name    TEXT,
    platform      TEXT,
    os_version    TEXT,
    app_version    TEXT,
    push_token    TEXT,
    first_seen_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_seen_at   TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at     TIMESTAMPTZ,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS messages (
    id                   TEXT PRIMARY KEY,
    client_msg_id        TEXT NOT NULL,
    sender_account_id    BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    recipient_account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    text                 TEXT NOT NULL,
    state                SMALLINT NOT NULL,
    created_at           TIMESTAMPTZ NOT NULL
);

CREATE TABLE IF NOT EXISTS account_seq_counters (
    account_id  BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
    current_seq BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS account_updates (
    account_id  BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    seq         BIGINT NOT NULL,
    kind        SMALLINT NOT NULL,
    payload     BYTEA NOT NULL,
    created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    PRIMARY KEY (account_id, seq)
);

CREATE TABLE IF NOT EXISTS auth_identities (
    id                BIGSERIAL PRIMARY KEY,
    account_id        BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    provider          TEXT NOT NULL,
    provider_user_id  TEXT NOT NULL,
    provider_email    TEXT,
    metadata          JSONB NOT NULL DEFAULT '{}'::jsonb,
    created_at        TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at        TIMESTAMPTZ NOT NULL DEFAULT now(),

    UNIQUE (provider, provider_user_id)
);

CREATE TABLE IF NOT EXISTS sessions (
    id              TEXT PRIMARY KEY,
    account_id      BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
    device_id       BIGINT NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
    connection_id   TEXT,
    created_at      TIMESTAMPTZ NOT NULL DEFAULT now(),
    last_active_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
    revoked_at      TIMESTAMPTZ
);

CREATE UNIQUE INDEX IF NOT EXISTS idx_devices_fingerprint_account ON devices(account_id, fingerprint) WHERE fingerprint IS NOT NULL;
CREATE INDEX IF NOT EXISTS idx_auth_identities_account_id ON auth_identities(account_id);
CREATE INDEX IF NOT EXISTS idx_sessions_account_id ON sessions(account_id) WHERE revoked_at IS NULL;
CREATE INDEX IF NOT EXISTS idx_sessions_last_active_at ON sessions(last_active_at) WHERE revoked_at IS NULL;
