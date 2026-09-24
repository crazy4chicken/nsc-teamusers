-- +goose Up

CREATE EXTENSION IF NOT EXISTS citext;

CREATE TABLE users (
    id TEXT PRIMARY KEY,
    username CITEXT NOT NULL UNIQUE,
    email CITEXT,
    display_name TEXT NOT NULL DEFAULT '',
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    perm_ver BIGINT NOT NULL DEFAULT 0,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE credentials (
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    kind TEXT NOT NULL,
    hash TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
    rotated_at TIMESTAMPTZ,
    PRIMARY KEY (user_id, kind)
);

CREATE TABLE teams (
    id TEXT PRIMARY KEY,
    slug TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'active' CHECK (status IN ('active', 'disabled')),
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE groups (
    id TEXT PRIMARY KEY,
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE (team_id, name)
);

CREATE TABLE memberships (
    team_id TEXT NOT NULL REFERENCES teams(id) ON DELETE CASCADE,
    group_id TEXT NOT NULL REFERENCES groups(id) ON DELETE CASCADE,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    expires_at TIMESTAMPTZ,
    PRIMARY KEY (group_id, user_id)
);

CREATE TABLE permissions (
    key TEXT PRIMARY KEY,
    description TEXT NOT NULL DEFAULT '',
    registered_by TEXT NOT NULL,
    created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE roles (
    id TEXT PRIMARY KEY,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    name TEXT NOT NULL,
    UNIQUE (team_id, name)
);

CREATE TABLE role_permissions (
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    permission_key TEXT NOT NULL REFERENCES permissions(key) ON DELETE CASCADE,
    PRIMARY KEY (role_id, permission_key)
);

CREATE TYPE role_binding_subject_kind AS ENUM ('group', 'user');

CREATE TABLE role_bindings (
    id TEXT PRIMARY KEY,
    team_id TEXT REFERENCES teams(id) ON DELETE CASCADE,
    role_id TEXT NOT NULL REFERENCES roles(id) ON DELETE CASCADE,
    subject_kind role_binding_subject_kind NOT NULL CHECK (subject_kind IN ('group', 'user')),
    subject_id TEXT NOT NULL,
    condition TEXT,
    expires_at TIMESTAMPTZ
);

CREATE TABLE sessions (
    id TEXT PRIMARY KEY,
    user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    family_id TEXT NOT NULL,
    client_meta JSONB NOT NULL DEFAULT '{}'::jsonb,
    expires_at TIMESTAMPTZ NOT NULL,
    revoked_at TIMESTAMPTZ,
    revoke_reason TEXT
);

CREATE TABLE audit_log (
    id BIGSERIAL PRIMARY KEY,
    team_id TEXT,
    actor_id TEXT,
    action TEXT NOT NULL,
    target TEXT NOT NULL,
    diff JSONB NOT NULL DEFAULT '{}'::jsonb,
    request_id TEXT,
    at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Audit log writes are append-only by contract. The deployment role should not
-- receive UPDATE or DELETE privileges on this table; no application code issues
-- either operation.

CREATE TABLE outbox (
    id BIGSERIAL PRIMARY KEY,
    topic TEXT NOT NULL,
    payload JSONB NOT NULL,
    published_at TIMESTAMPTZ
);

CREATE TABLE permission_registry_meta (
    id BOOLEAN PRIMARY KEY DEFAULT TRUE CHECK (id),
    perm_ver BIGINT NOT NULL DEFAULT 0,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

INSERT INTO permission_registry_meta (id, perm_ver)
VALUES (TRUE, 0);

CREATE INDEX memberships_user_id_idx ON memberships (user_id);
CREATE INDEX role_bindings_subject_idx ON role_bindings (subject_kind, subject_id);
CREATE INDEX audit_log_team_at_idx ON audit_log (team_id, at DESC);
CREATE INDEX outbox_unpublished_idx ON outbox (published_at) WHERE published_at IS NULL;

-- +goose Down

DROP TABLE IF EXISTS outbox;
DROP TABLE IF EXISTS permission_registry_meta;
DROP TABLE IF EXISTS audit_log;
DROP TABLE IF EXISTS sessions;
DROP TABLE IF EXISTS role_bindings;
DROP TYPE IF EXISTS role_binding_subject_kind;
DROP TABLE IF EXISTS role_permissions;
DROP TABLE IF EXISTS roles;
DROP TABLE IF EXISTS permissions;
DROP TABLE IF EXISTS memberships;
DROP TABLE IF EXISTS groups;
DROP TABLE IF EXISTS teams;
DROP TABLE IF EXISTS credentials;
DROP TABLE IF EXISTS users;
