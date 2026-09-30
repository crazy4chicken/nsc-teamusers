-- +goose NO TRANSACTION
-- +goose Up

CREATE TABLE oidc_identities (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    issuer TEXT NOT NULL,
    sub TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS oidc_identities_issuer_sub_idx ON oidc_identities (issuer, sub);
CREATE INDEX CONCURRENTLY IF NOT EXISTS oidc_identities_user_id_idx ON oidc_identities (user_id);

CREATE TABLE oidc_login_states (
    state_hash TEXT NOT NULL,
    nonce_hash TEXT NOT NULL,
    expires_at TIMESTAMPTZ NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS oidc_login_states_state_hash_idx ON oidc_login_states (state_hash);
CREATE INDEX CONCURRENTLY IF NOT EXISTS oidc_login_states_expiry_idx ON oidc_login_states (expires_at);

ALTER TABLE login_activity DROP CONSTRAINT login_activity_method_check;
ALTER TABLE login_activity ADD CONSTRAINT login_activity_method_check
    CHECK (method IN ('password', 'passkey', 'mfa', 'oidc'));

-- +goose Down

DELETE FROM login_activity WHERE method = 'oidc';
ALTER TABLE login_activity DROP CONSTRAINT login_activity_method_check;
ALTER TABLE login_activity ADD CONSTRAINT login_activity_method_check
    CHECK (method IN ('password', 'passkey', 'mfa'));

DROP INDEX CONCURRENTLY IF EXISTS oidc_login_states_expiry_idx;
DROP INDEX CONCURRENTLY IF EXISTS oidc_login_states_state_hash_idx;
DROP TABLE IF EXISTS oidc_login_states;
DROP INDEX CONCURRENTLY IF EXISTS oidc_identities_user_id_idx;
DROP INDEX CONCURRENTLY IF EXISTS oidc_identities_issuer_sub_idx;
DROP TABLE IF EXISTS oidc_identities;
