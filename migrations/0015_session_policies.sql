-- +goose NO TRANSACTION
-- +goose Up

ALTER TABLE sessions
    ADD COLUMN last_active_at TIMESTAMPTZ NOT NULL DEFAULT now();
UPDATE sessions SET last_active_at = created_at;

CREATE INDEX CONCURRENTLY IF NOT EXISTS sessions_active_user_created_at_idx
	ON sessions (user_id, created_at, id)
	WHERE revoked_at IS NULL;

CREATE TABLE session_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('default','team','group','role')),
    subject_id TEXT NOT NULL DEFAULT '',
    max_concurrent_sessions INTEGER CHECK (max_concurrent_sessions IS NULL OR max_concurrent_sessions > 0),
    idle_timeout_minutes INTEGER CHECK (idle_timeout_minutes IS NULL OR idle_timeout_minutes > 0),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (subject_kind = 'default' AND subject_id = '')
        OR (subject_kind <> 'default' AND subject_id <> '')
    )
);
CREATE INDEX session_policies_subject_priority_idx ON session_policies (subject_kind, subject_id, priority DESC, id ASC);

-- +goose Down
DROP INDEX CONCURRENTLY IF EXISTS sessions_active_user_created_at_idx;

DROP TABLE IF EXISTS session_policies;
ALTER TABLE sessions DROP COLUMN IF EXISTS last_active_at;
