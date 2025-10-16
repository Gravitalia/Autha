-- Token logic.

CREATE TABLE IF NOT EXISTS tokens (
  token       TEXT        PRIMARY KEY,
  user_id     TEXT        NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  ip          TEXT, -- Could be blank if anonymity is important.
  created_at  DATE        NOT NULL DEFAULT NOW(),
  expire_at   TIMESTAMPTZ NOT NULL DEFAULT NOW() + '15 days'
)
