-- +goose Up

CREATE TABLE webauthn_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    challenge TEXT NOT NULL UNIQUE,
    session_data JSONB NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX webauthn_challenges_expires_at_idx ON webauthn_challenges (expires_at);

-- +goose Down

DROP TABLE IF EXISTS webauthn_challenges;
