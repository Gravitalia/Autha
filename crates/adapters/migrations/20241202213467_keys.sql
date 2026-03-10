-- Public keys table logic.

CREATE TABLE IF NOT EXISTS keys (
  id            SERIAL  PRIMARY KEY,
  user_id       TEXT    REFERENCES users(id) ON DELETE CASCADE,
  device_name   TEXT    NOT NULL DEFAULT 'unknown',
  pem           TEXT    NOT NULL UNIQUE,
  created_at    DATE    NOT NULL DEFAULT NOW()
);

CREATE INDEX idx_keys_user_id ON keys(user_id);
