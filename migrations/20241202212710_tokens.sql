-- Token logic.

CREATE TABLE IF NOT EXISTS tokens (
  token       TEXT        PRIMARY KEY,
  user_vanity TEXT        NOT NULL REFERENCES users(vanity) ON DELETE CASCADE,
  ip          TEXT, -- Could be blank if anonymity is important.
  created_at  DATE        NOT NULL DEFAULT NOW(),
  expire_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + '1 month'
)
