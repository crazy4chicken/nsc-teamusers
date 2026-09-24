-- +goose Up

ALTER TABLE sessions ADD COLUMN family_not_after TIMESTAMPTZ;
UPDATE sessions SET family_not_after = expires_at WHERE family_not_after IS NULL;
ALTER TABLE sessions ALTER COLUMN family_not_after SET NOT NULL;
CREATE INDEX sessions_family_id_idx ON sessions (family_id);

-- +goose Down

DROP INDEX IF EXISTS sessions_family_id_idx;
ALTER TABLE sessions DROP COLUMN IF EXISTS family_not_after;
