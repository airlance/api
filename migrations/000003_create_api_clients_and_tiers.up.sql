-- 000003_create_api_clients_and_tiers.up.sql

CREATE TABLE IF NOT EXISTS rate_limit_tiers (
    id UUID PRIMARY KEY,
    name TEXT NOT NULL UNIQUE,
    requests_per_minute INTEGER NOT NULL CHECK (requests_per_minute > 0),
    requests_per_day INTEGER NOT NULL CHECK (requests_per_day > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Seed default tier
INSERT INTO rate_limit_tiers (id, name, requests_per_minute, requests_per_day)
VALUES ('00000000-0000-0000-0000-000000000001', 'default', 60, 5000)
ON CONFLICT (name) DO NOTHING;

CREATE TABLE IF NOT EXISTS api_clients (
    id UUID PRIMARY KEY,
    user_id UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    tier_id UUID NOT NULL REFERENCES rate_limit_tiers(id),
    name TEXT NOT NULL,
    secret_hash BYTEA NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at TIMESTAMPTZ NULL
);

CREATE INDEX IF NOT EXISTS idx_api_clients_user_id ON api_clients(user_id);
CREATE UNIQUE INDEX IF NOT EXISTS idx_api_clients_user_id_name_unrevoked 
ON api_clients(user_id, name) WHERE revoked_at IS NULL;
