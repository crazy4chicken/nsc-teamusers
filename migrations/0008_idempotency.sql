-- +goose Up

CREATE TABLE idempotency_keys (
    scope TEXT NOT NULL,
    key TEXT NOT NULL,
    fingerprint TEXT NOT NULL,
    status INTEGER NULL,
    response BYTEA NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    expires_at TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (scope, key)
);

-- +goose Down

DROP TABLE IF EXISTS idempotency_keys;
