-- +goose Up

CREATE TABLE password_history (
    history_id BIGINT GENERATED ALWAYS AS IDENTITY PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    hash TEXT NOT NULL,
    set_at TIMESTAMPTZ NOT NULL
);
CREATE INDEX password_history_user_set_at_idx ON password_history (user_id, set_at DESC, history_id DESC);

ALTER TABLE password_policies
    ADD COLUMN history_count INTEGER CHECK (history_count IS NULL OR history_count BETWEEN 0 AND 24),
    ADD COLUMN breach_check BOOLEAN;

INSERT INTO password_history (user_id, hash, set_at)
SELECT user_id, hash, COALESCE(rotated_at, created_at)
FROM credentials
WHERE kind = 'password';

-- +goose Down

ALTER TABLE password_policies
    DROP COLUMN breach_check,
    DROP COLUMN history_count;

DROP TABLE IF EXISTS password_history;
