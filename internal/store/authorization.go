package store

import (
	"context"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func CreatePermission(ctx context.Context, q Q, permission Permission) (Permission, error) {
	return scanPermission(q.QueryRow(ctx, `
		INSERT INTO permissions (key, description, registered_by)
		VALUES ($1, $2, $3)
		RETURNING key, description, registered_by, created_at`,
		permission.Key, permission.Description, permission.RegisteredBy))
}

func GetPermission(ctx context.Context, q Q, key string) (Permission, error) {
	return scanPermission(q.QueryRow(ctx, `
		SELECT key, description, registered_by, created_at
		FROM permissions WHERE key = $1`, key))
}

func ListPermissions(ctx context.Context, q Q, cursor string, limit int) ([]Permission, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT key, description, registered_by, created_at FROM permissions
			ORDER BY key LIMIT $1`, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT key, description, registered_by, created_at FROM permissions
			WHERE key > $1 ORDER BY key LIMIT $2`, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	permissions := make([]Permission, 0, limit)
	for rows.Next() {
		permission, err := scanPermission(rows)
		if err != nil {
			return nil, "", err
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return permissions, nextCursor(len(permissions), limit, func(i int) string { return permissions[i].Key }), nil
}

func UpdatePermission(ctx context.Context, q Q, permission Permission) (Permission, error) {
	return scanPermission(q.QueryRow(ctx, `
		UPDATE permissions SET description = $2, registered_by = $3
		WHERE key = $1
		RETURNING key, description, registered_by, created_at`,
		permission.Key, permission.Description, permission.RegisteredBy))
}

func DeletePermission(ctx context.Context, q Q, key string) error {
	_, err := q.Exec(ctx, `DELETE FROM permissions WHERE key = $1`, key)
	return err
}

func CreateRole(ctx context.Context, q Q, role Role) (Role, error) {
	if role.ID == "" {
		role.ID = NewID()
	}
	return scanRole(q.QueryRow(ctx, `
		INSERT INTO roles (id, team_id, name)
		VALUES ($1, $2, $3)
		RETURNING id, team_id, name`, role.ID, role.TeamID, role.Name))
}

func GetRole(ctx context.Context, q Q, id string) (Role, error) {
	return scanRole(q.QueryRow(ctx, `
		SELECT id, team_id, name FROM roles WHERE id = $1`, id))
}

func ListRoles(ctx context.Context, q Q, teamID *string, cursor string, limit int) ([]Role, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	switch {
	case teamID == nil && cursor == "":
		rows, err = q.Query(ctx, `SELECT id, team_id, name FROM roles ORDER BY id LIMIT $1`, limit)
	case teamID == nil:
		rows, err = q.Query(ctx, `SELECT id, team_id, name FROM roles WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	case cursor == "":
		rows, err = q.Query(ctx, `SELECT id, team_id, name FROM roles WHERE team_id IS NOT DISTINCT FROM $1 ORDER BY id LIMIT $2`, *teamID, limit)
	default:
		rows, err = q.Query(ctx, `SELECT id, team_id, name FROM roles WHERE team_id IS NOT DISTINCT FROM $1 AND id > $2 ORDER BY id LIMIT $3`, *teamID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	roles := make([]Role, 0, limit)
	for rows.Next() {
		role, err := scanRole(rows)
		if err != nil {
			return nil, "", err
		}
		roles = append(roles, role)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return roles, nextCursor(len(roles), limit, func(i int) string { return roles[i].ID }), nil
}

func UpdateRole(ctx context.Context, q Q, role Role) (Role, error) {
	return scanRole(q.QueryRow(ctx, `
		UPDATE roles SET team_id = $2, name = $3
		WHERE id = $1 RETURNING id, team_id, name`, role.ID, role.TeamID, role.Name))
}

func DeleteRole(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM roles WHERE id = $1`, id)
	return err
}

// SetRolePermissions replaces all permission rows for a role. Callers that
// require atomicity should invoke this helper through WithTx.
func SetRolePermissions(ctx context.Context, q Q, roleID string, permissionKeys []string) error {
	if _, err := q.Exec(ctx, `DELETE FROM role_permissions WHERE role_id = $1`, roleID); err != nil {
		return err
	}
	for _, permissionKey := range permissionKeys {
		if _, err := q.Exec(ctx, `
			INSERT INTO role_permissions (role_id, permission_key)
			VALUES ($1, $2)`, roleID, permissionKey); err != nil {
			return err
		}
	}
	return nil
}

func ListRolePermissions(ctx context.Context, q Q, roleID, cursor string, limit int) ([]string, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT permission_key FROM role_permissions
			WHERE role_id = $1 ORDER BY permission_key LIMIT $2`, roleID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT permission_key FROM role_permissions
			WHERE role_id = $1 AND permission_key > $2 ORDER BY permission_key LIMIT $3`, roleID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	permissions := make([]string, 0, limit)
	for rows.Next() {
		var permission string
		if err := rows.Scan(&permission); err != nil {
			return nil, "", err
		}
		permissions = append(permissions, permission)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return permissions, nextCursor(len(permissions), limit, func(i int) string { return permissions[i] }), nil
}

func CreateRoleBinding(ctx context.Context, q Q, binding RoleBinding) (RoleBinding, error) {
	if binding.ID == "" {
		binding.ID = NewID()
	}
	return scanRoleBinding(q.QueryRow(ctx, `
		INSERT INTO role_bindings (id, team_id, role_id, subject_kind, subject_id, condition, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, team_id, role_id, subject_kind, subject_id, condition, expires_at`,
		binding.ID, binding.TeamID, binding.RoleID, binding.SubjectKind, binding.SubjectID,
		binding.Condition, binding.ExpiresAt))
}

func GetRoleBinding(ctx context.Context, q Q, id string) (RoleBinding, error) {
	return scanRoleBinding(q.QueryRow(ctx, `
		SELECT id, team_id, role_id, subject_kind, subject_id, condition, expires_at
		FROM role_bindings WHERE id = $1`, id))
}

func DeleteRoleBinding(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM role_bindings WHERE id = $1`, id)
	return err
}

func ListRoleBindingsBySubject(ctx context.Context, q Q, subjectKind, subjectID, cursor string, limit int) ([]RoleBinding, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT id, team_id, role_id, subject_kind, subject_id, condition, expires_at
			FROM role_bindings WHERE subject_kind = $1 AND subject_id = $2
			ORDER BY id LIMIT $3`, subjectKind, subjectID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, team_id, role_id, subject_kind, subject_id, condition, expires_at
			FROM role_bindings WHERE subject_kind = $1 AND subject_id = $2 AND id > $3
			ORDER BY id LIMIT $4`, subjectKind, subjectID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	bindings := make([]RoleBinding, 0, limit)
	for rows.Next() {
		binding, err := scanRoleBinding(rows)
		if err != nil {
			return nil, "", err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return bindings, nextCursor(len(bindings), limit, func(i int) string { return bindings[i].ID }), nil
}

func BumpUserPermVer(ctx context.Context, q Q, userID string) (int64, error) {
	var version int64
	if err := q.QueryRow(ctx, `
		UPDATE users SET perm_ver = perm_ver + 1, updated_at = updated_at
		WHERE id = $1 RETURNING perm_ver`, userID).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func GetUserPermVer(ctx context.Context, q Q, userID string) (int64, error) {
	var version int64
	if err := q.QueryRow(ctx, `SELECT perm_ver FROM users WHERE id = $1`, userID).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

// BumpPermVer is an alias with the concise name used by cache callers.
func BumpPermVer(ctx context.Context, q Q, userID string) (int64, error) {
	return BumpUserPermVer(ctx, q, userID)
}

func GetPermissionRegistryPermVer(ctx context.Context, q Q) (int64, error) {
	var version int64
	if err := q.QueryRow(ctx, `SELECT perm_ver FROM permission_registry_meta WHERE id = TRUE`).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func BumpPermissionRegistryPermVer(ctx context.Context, q Q) (int64, error) {
	var version int64
	if err := q.QueryRow(ctx, `
		UPDATE permission_registry_meta
		SET perm_ver = perm_ver + 1, updated_at = now()
		WHERE id = TRUE RETURNING perm_ver`).Scan(&version); err != nil {
		return 0, err
	}
	return version, nil
}

func scanPermission(row pgx.Row) (Permission, error) {
	var permission Permission
	if err := row.Scan(&permission.Key, &permission.Description, &permission.RegisteredBy, &permission.CreatedAt); err != nil {
		return Permission{}, err
	}
	return permission, nil
}

func scanRole(row pgx.Row) (Role, error) {
	var role Role
	var teamID pgtype.Text
	if err := row.Scan(&role.ID, &teamID, &role.Name); err != nil {
		return Role{}, err
	}
	role.TeamID = textPointer(teamID)
	return role, nil
}

func scanRoleBinding(row pgx.Row) (RoleBinding, error) {
	var binding RoleBinding
	var teamID, condition pgtype.Text
	if err := row.Scan(
		&binding.ID, &teamID, &binding.RoleID, &binding.SubjectKind,
		&binding.SubjectID, &condition, &binding.ExpiresAt,
	); err != nil {
		return RoleBinding{}, err
	}
	binding.TeamID = textPointer(teamID)
	binding.Condition = textPointer(condition)
	return binding, nil
}
