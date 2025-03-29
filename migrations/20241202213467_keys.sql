-- Public keys table logic.

CREATE TABLE IF NOT EXISTS keys (
  id            SERIAL  PRIMARY KEY,
  user_id       TEXT    REFERENCES users(id) ON DELETE CASCADE,
  key           TEXT    NOT NULL,
  created_at    DATE    NOT NULL DEFAULT NOW()
);

CREATE INDEX key_idx ON keys (key) INCLUDE (id);
