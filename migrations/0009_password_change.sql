-- +goose Up

ALTER TABLE credentials
    ADD COLUMN must_change BOOLEAN NOT NULL DEFAULT false;

-- +goose Down

ALTER TABLE credentials
    DROP COLUMN IF EXISTS must_change;
