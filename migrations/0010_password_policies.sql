-- +goose Up

CREATE TABLE password_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('user','team','group','role')),
    subject_id TEXT NOT NULL,
    min_length INTEGER CHECK (min_length IS NULL OR min_length BETWEEN 1 AND 1024),
    require_letter BOOLEAN,
    require_upper BOOLEAN,
    require_lower BOOLEAN,
    require_digit BOOLEAN,
    require_symbol BOOLEAN,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);
CREATE INDEX password_policies_subject_idx ON password_policies (subject_kind, subject_id);

-- +goose Down

DROP TABLE IF EXISTS password_policies;
