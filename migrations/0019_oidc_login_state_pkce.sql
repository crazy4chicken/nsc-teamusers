-- +goose Up

ALTER TABLE oidc_login_states
    ADD COLUMN code_challenge TEXT NOT NULL DEFAULT '',
    ADD COLUMN code_verifier TEXT NOT NULL DEFAULT '';
ALTER TABLE oidc_login_states
    ALTER COLUMN code_challenge DROP DEFAULT,
    ALTER COLUMN code_verifier DROP DEFAULT;

-- +goose Down

ALTER TABLE oidc_login_states
    DROP COLUMN code_verifier,
    DROP COLUMN code_challenge;
