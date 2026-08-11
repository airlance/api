CREATE TABLE account_seq_counters (
  account_id  BIGINT PRIMARY KEY REFERENCES accounts(id) ON DELETE CASCADE,
  current_seq BIGINT NOT NULL DEFAULT 0
);

CREATE TABLE account_updates (
  account_id  BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  seq         BIGINT NOT NULL,
  kind        SMALLINT NOT NULL,
  payload     BYTEA NOT NULL,
  created_at  TIMESTAMPTZ NOT NULL DEFAULT now(),
  PRIMARY KEY (account_id, seq)
);
