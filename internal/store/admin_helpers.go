package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// UpsertPermission registers a permission key without changing its immutable
// identity. Description and registration metadata are refreshed on conflict.
func UpsertPermission(ctx context.Context, q Q, permission Permission) (Permission, error) {
	return scanPermission(q.QueryRow(ctx, `
		INSERT INTO permissions (key, description, registered_by)
		VALUES ($1, $2, $3)
		ON CONFLICT (key) DO UPDATE
		SET description = EXCLUDED.description, registered_by = EXCLUDED.registered_by
		RETURNING key, description, registered_by, created_at`,
		permission.Key, permission.Description, permission.RegisteredBy))
}

// GetMembership retrieves one group membership.
func GetMembership(ctx context.Context, q Q, groupID, userID string) (Membership, error) {
	return scanMembership(q.QueryRow(ctx, `
		SELECT team_id, group_id, user_id, expires_at
		FROM memberships WHERE group_id = $1 AND user_id = $2`, groupID, userID))
}

// UpdateGroupMembershipTeam keeps denormalized membership tenancy aligned
// when a group is moved between teams.
func UpdateGroupMembershipTeam(ctx context.Context, q Q, groupID, teamID string) error {
	_, err := q.Exec(ctx, `UPDATE memberships SET team_id = $2 WHERE group_id = $1`, groupID, teamID)
	return err
}

// ListUserIDsByGroup returns all users whose effective permissions may change
// when a group binding or membership changes.
func ListUserIDsByGroup(ctx context.Context, q Q, groupID string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT user_id FROM memberships WHERE group_id = $1 ORDER BY user_id`, groupID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserIDs(rows)
}

// ListUserIDsByRole returns users affected by a role permission or binding
// change, including direct user bindings and group members.
func ListUserIDsByRole(ctx context.Context, q Q, roleID string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT user_id FROM (
			SELECT subject_id AS user_id
			FROM role_bindings
			WHERE role_id = $1 AND subject_kind = 'user'
			UNION ALL
			SELECT m.user_id
			FROM role_bindings b
			JOIN memberships m ON m.group_id = b.subject_id
			WHERE b.role_id = $1 AND b.subject_kind = 'group'
		) affected
		ORDER BY user_id`, roleID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserIDs(rows)
}

// ListUserIDsByTeam returns users whose effective permissions can be removed
// when a team and its groups, memberships, or team bindings are deleted.
func ListUserIDsByTeam(ctx context.Context, q Q, teamID string) ([]string, error) {
	rows, err := q.Query(ctx, `
		SELECT DISTINCT user_id FROM (
			SELECT user_id
			FROM memberships
			WHERE team_id = $1
			UNION ALL
			SELECT subject_id AS user_id
			FROM role_bindings
			WHERE team_id = $1 AND subject_kind = 'user'
			UNION ALL
			SELECT m.user_id
			FROM role_bindings b
			JOIN groups g ON g.id = b.subject_id AND b.subject_kind = 'group'
			JOIN memberships m ON m.group_id = g.id
			WHERE g.team_id = $1
		) affected
		ORDER BY user_id`, teamID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanUserIDs(rows)
}

// ListUserIDsByBinding returns users affected by a binding before it is
// deleted or after it is created.
func ListUserIDsByBinding(ctx context.Context, q Q, binding RoleBinding) ([]string, error) {
	if binding.SubjectKind == "user" {
		return []string{binding.SubjectID}, nil
	}
	return ListUserIDsByGroup(ctx, q, binding.SubjectID)
}

// RevokeAllUserSessions revokes every active refresh-token session for a user.
func RevokeAllUserSessions(ctx context.Context, q Q, userID, reason string) error {
	_, err := q.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL`, userID, reason)
	return err
}

func scanUserIDs(rows pgx.Rows) ([]string, error) {
	ids := make([]string, 0)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return ids, nil
}
