-- +goose Up

ALTER TABLE role_bindings
    DROP CONSTRAINT role_bindings_subject_kind_check;
ALTER TABLE role_bindings
    ALTER COLUMN subject_kind TYPE TEXT USING subject_kind::text;
DROP TYPE role_binding_subject_kind;
CREATE TYPE role_binding_subject_kind AS ENUM ('group', 'user', 'team');
ALTER TABLE role_bindings
    ALTER COLUMN subject_kind TYPE role_binding_subject_kind USING subject_kind::role_binding_subject_kind;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_subject_kind_check
    CHECK (subject_kind IN ('group', 'user', 'team'));
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_team_baseline_check
    CHECK (
        subject_kind <> 'team'
        OR (team_id IS NOT NULL AND team_id = subject_id AND expires_at IS NULL)
    );
CREATE UNIQUE INDEX role_bindings_one_team_baseline_idx
    ON role_bindings (team_id)
    WHERE subject_kind = 'team';

-- +goose Down

-- +goose StatementBegin
DO $$
BEGIN
    IF EXISTS (SELECT 1 FROM role_bindings WHERE subject_kind = 'team') THEN
        RAISE EXCEPTION 'cannot roll back team baseline migration while team baseline bindings remain';
    END IF;
END $$;
-- +goose StatementEnd

DROP INDEX role_bindings_one_team_baseline_idx;
ALTER TABLE role_bindings
    DROP CONSTRAINT role_bindings_team_baseline_check;
ALTER TABLE role_bindings
    DROP CONSTRAINT role_bindings_subject_kind_check;
ALTER TABLE role_bindings
    ALTER COLUMN subject_kind TYPE TEXT USING subject_kind::text;
DROP TYPE role_binding_subject_kind;
CREATE TYPE role_binding_subject_kind AS ENUM ('group', 'user');
ALTER TABLE role_bindings
    ALTER COLUMN subject_kind TYPE role_binding_subject_kind USING subject_kind::role_binding_subject_kind;
ALTER TABLE role_bindings
    ADD CONSTRAINT role_bindings_subject_kind_check
    CHECK (subject_kind IN ('group', 'user'));
