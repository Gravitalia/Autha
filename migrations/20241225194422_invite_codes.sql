-- Inivtation table logic.

CREATE TABLE IF NOT EXISTS invite_codes (
  code        TEXT        PRIMARY KEY,
  used_by     TEXT        REFERENCES users(vanity),
  used_at     TIMESTAMP,
  created_at  DATE        NOT NULL DEFAULT NOW()
);
