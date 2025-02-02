-- Public keys table logic.

CREATE TABLE IF NOT EXISTS keys (
  id            SERIAL  PRIMARY KEY,
  key           TEXT    NOT NULL,
  created_at    DATE    NOT NULL DEFAULT NOW(),
);
