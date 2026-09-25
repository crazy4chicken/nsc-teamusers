-- +goose Up

ALTER TABLE users
    ADD COLUMN failed_logins INTEGER NOT NULL DEFAULT 0,
    ADD COLUMN locked_until TIMESTAMPTZ;

-- +goose Down

ALTER TABLE users
    DROP COLUMN IF EXISTS locked_until,
    DROP COLUMN IF EXISTS failed_logins;

