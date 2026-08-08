-- Initial schema. Replace / extend with real tables as the domain grows.
CREATE TABLE IF NOT EXISTS schema_bootstrap (
    id         SERIAL PRIMARY KEY,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
