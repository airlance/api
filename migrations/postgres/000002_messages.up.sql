CREATE TABLE messages (
  id                   TEXT PRIMARY KEY,
  client_msg_id        TEXT NOT NULL,
  sender_account_id    BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  recipient_account_id BIGINT NOT NULL REFERENCES accounts(id) ON DELETE CASCADE,
  text                 TEXT NOT NULL,
  state                SMALLINT NOT NULL,
  created_at           TIMESTAMPTZ NOT NULL
);
