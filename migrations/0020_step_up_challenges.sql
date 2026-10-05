-- +goose Up

CREATE TABLE step_up_challenges (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    session_id TEXT NOT NULL REFERENCES sessions(id) ON DELETE CASCADE,
    purpose TEXT NOT NULL CHECK (purpose = 'step_up'),
    methods TEXT[] NOT NULL CHECK (cardinality(methods) > 0),
    webauthn_session JSONB,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX step_up_challenges_expires_at_idx ON step_up_challenges (expires_at);

-- +goose Down

DROP TABLE IF EXISTS step_up_challenges;
