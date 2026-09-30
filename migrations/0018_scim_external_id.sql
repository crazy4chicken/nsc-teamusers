-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE users ADD COLUMN IF NOT EXISTS external_id TEXT NULL;
CREATE UNIQUE INDEX CONCURRENTLY IF NOT EXISTS users_external_id_uq_idx
    ON users (external_id) WHERE external_id IS NOT NULL;

-- +goose Down

DROP INDEX CONCURRENTLY IF EXISTS users_external_id_uq_idx;
ALTER TABLE users DROP COLUMN IF EXISTS external_id;
