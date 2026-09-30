-- +goose Up

CREATE TABLE mfa_policies (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL DEFAULT '',
    priority INTEGER NOT NULL DEFAULT 0,
    subject_kind TEXT NOT NULL CHECK (subject_kind IN ('default','team','group','role')),
    subject_id TEXT NOT NULL DEFAULT '',
    required BOOLEAN NOT NULL DEFAULT FALSE,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    CHECK (
        (subject_kind = 'default' AND subject_id = '')
        OR (subject_kind <> 'default' AND subject_id <> '')
    )
);
CREATE INDEX mfa_policies_subject_priority_idx ON mfa_policies (subject_kind, subject_id, priority DESC, id ASC);

-- +goose Down

DROP TABLE IF EXISTS mfa_policies;
