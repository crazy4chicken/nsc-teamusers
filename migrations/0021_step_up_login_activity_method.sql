-- +goose Up

ALTER TABLE login_activity DROP CONSTRAINT login_activity_method_check;
ALTER TABLE login_activity ADD CONSTRAINT login_activity_method_check
    CHECK (method IN ('password', 'passkey', 'mfa', 'oidc', 'step_up'));

-- +goose Down

UPDATE login_activity
SET method = 'mfa'
WHERE method = 'step_up';

ALTER TABLE login_activity DROP CONSTRAINT login_activity_method_check;
ALTER TABLE login_activity ADD CONSTRAINT login_activity_method_check
    CHECK (method IN ('password', 'passkey', 'mfa', 'oidc'));
