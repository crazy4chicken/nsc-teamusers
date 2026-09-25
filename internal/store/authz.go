package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

// ListDirectRoleBindings returns active direct user bindings that are either
// platform scoped or scoped to a team in which the user has an active
// membership.
func ListDirectRoleBindings(ctx context.Context, q Q, userID string, now time.Time) ([]RoleBinding, error) {
	rows, err := q.Query(ctx, `
		SELECT b.id, b.team_id, b.role_id, b.subject_kind, b.subject_id, b.condition, b.expires_at
		FROM role_bindings b
		WHERE b.subject_kind = 'user' AND b.subject_id = $1
		  AND (b.expires_at IS NULL OR b.expires_at > $2)
		  AND (
			b.team_id IS NULL
			OR EXISTS (
				SELECT 1
				FROM memberships m
				WHERE m.user_id = $1
				  AND m.team_id = b.team_id
				  AND (m.expires_at IS NULL OR m.expires_at > $2)
			)
		  )
		ORDER BY b.id`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuthzRoleBindings(rows)
}

// ListGroupRoleBindings returns active group bindings inherited by the user's
// active memberships. The membership join keeps this path to one query even
// when a user belongs to many groups.
func ListGroupRoleBindings(ctx context.Context, q Q, userID string, now time.Time) ([]RoleBinding, error) {
	rows, err := q.Query(ctx, `
		SELECT b.id, b.team_id, b.role_id, b.subject_kind, b.subject_id, b.condition, b.expires_at
		FROM role_bindings b
		JOIN memberships m ON m.group_id = b.subject_id
		WHERE b.subject_kind = 'group' AND m.user_id = $1
		  AND (m.expires_at IS NULL OR m.expires_at > $2)
		  AND (b.expires_at IS NULL OR b.expires_at > $2)
		  AND (b.team_id IS NULL OR b.team_id = m.team_id)
		ORDER BY b.id`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuthzRoleBindings(rows)
}

// ListRolePermissionsForRoles batches all role permission expansion for an
// effective set. Callers should pass unique role IDs; the helper is also safe
// with duplicates and returns an empty map when there are no roles.
func ListRolePermissionsForRoles(ctx context.Context, q Q, roleIDs []string) (map[string][]string, error) {
	permissions := make(map[string][]string, len(roleIDs))
	if len(roleIDs) == 0 {
		return permissions, nil
	}

	rows, err := q.Query(ctx, `
		SELECT role_id, permission_key
		FROM role_permissions
		WHERE role_id = ANY($1::text[])
		ORDER BY role_id, permission_key`, roleIDs)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	for rows.Next() {
		var roleID, permissionKey string
		if err := rows.Scan(&roleID, &permissionKey); err != nil {
			return nil, err
		}
		permissions[roleID] = append(permissions[roleID], permissionKey)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permissions, nil
}

// ListUnconditionalRolePermissions mirrors the grant selection in authz's
// resolver for the admin plane. It lives in store so httpapi can enforce
// permissions without importing authz, whose handlers import httpapi.
func ListUnconditionalRolePermissions(ctx context.Context, q Q, userID string, now time.Time) ([]string, error) {
	rows, err := q.Query(ctx, `
        SELECT DISTINCT rp.permission_key
        FROM role_permissions rp
        JOIN role_bindings b ON b.role_id = rp.role_id
        WHERE (b.expires_at IS NULL OR b.expires_at > $2)
          AND (b.condition IS NULL OR btrim(b.condition) = '')
          AND (
            (b.subject_kind = 'user' AND b.subject_id = $1 AND (
                b.team_id IS NULL OR EXISTS (
                    SELECT 1 FROM memberships m
                    WHERE m.user_id = $1 AND m.team_id = b.team_id
                      AND (m.expires_at IS NULL OR m.expires_at > $2)
                )
            ))
            OR (b.subject_kind = 'group' AND EXISTS (
                SELECT 1 FROM memberships m
                WHERE m.user_id = $1 AND m.group_id = b.subject_id
                  AND (m.expires_at IS NULL OR m.expires_at > $2)
                  AND (b.team_id IS NULL OR b.team_id = m.team_id)
            ))
          )
        ORDER BY rp.permission_key`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	permissions := make([]string, 0)
	for rows.Next() {
		var key string
		if err := rows.Scan(&key); err != nil {
			return nil, err
		}
		permissions = append(permissions, key)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return permissions, nil

}
func scanAuthzRoleBindings(rows pgx.Rows) ([]RoleBinding, error) {
	bindings := make([]RoleBinding, 0)
	for rows.Next() {
		binding, err := scanRoleBinding(rows)
		if err != nil {
			return nil, err
		}
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bindings, nil
}
