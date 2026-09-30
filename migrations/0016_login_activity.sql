-- +goose Up

CREATE TABLE login_activity (
    id BIGSERIAL PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    attempted_username TEXT NOT NULL DEFAULT '',
    at TIMESTAMPTZ NOT NULL DEFAULT now(),
    ip TEXT NOT NULL DEFAULT '',
    user_agent TEXT NOT NULL DEFAULT '',
    method TEXT NOT NULL CHECK (method IN ('password','passkey','mfa')),
    result TEXT NOT NULL CHECK (result IN ('success','failure'))
);
CREATE INDEX login_activity_user_at_idx ON login_activity (user_id, at DESC);
CREATE INDEX login_activity_user_id_idx ON login_activity (user_id, id DESC);

-- +goose Down

DROP TABLE IF EXISTS login_activity;
