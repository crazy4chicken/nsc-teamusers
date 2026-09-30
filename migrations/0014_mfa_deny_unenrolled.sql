-- +goose Up

ALTER TABLE mfa_policies
    ADD COLUMN deny_unenrolled BOOLEAN NOT NULL DEFAULT FALSE;

-- +goose Down

ALTER TABLE mfa_policies
    DROP COLUMN IF EXISTS deny_unenrolled;
