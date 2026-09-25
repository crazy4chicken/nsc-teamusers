-- +goose Up

ALTER TABLE sessions
    ADD COLUMN created_at TIMESTAMPTZ NOT NULL DEFAULT now();

-- +goose Down

ALTER TABLE sessions DROP COLUMN IF EXISTS created_at;
