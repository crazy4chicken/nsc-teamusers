-- +goose Up

ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'pending', 'invited'));

ALTER TABLE verification_tokens
    ADD COLUMN payload JSONB NULL;

-- +goose Down

UPDATE users SET status = 'disabled' WHERE status = 'invited';
ALTER TABLE users DROP CONSTRAINT users_status_check;
ALTER TABLE users ADD CONSTRAINT users_status_check CHECK (status IN ('active', 'disabled', 'pending'));

ALTER TABLE verification_tokens
    DROP COLUMN IF EXISTS payload;
