package store

import (
	"context"
	"fmt"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"

	"teamusers/internal/domain"
)

// ListDirectRoleBindings returns active direct user bindings. Team-scoped
// bindings require an active membership in an active team; platform bindings
// remain independent of membership and team status.
func ListDirectRoleBindings(ctx context.Context, q Q, userID string, now time.Time) ([]RoleBinding, error) {
	rows, err := q.Query(ctx, `
		SELECT b.id, b.team_id, b.role_id, b.subject_kind, b.subject_id, b.condition, b.expires_at,
			LEAST(b.expires_at, membership_exp.expires_at)
		FROM role_bindings b
		LEFT JOIN LATERAL (
			SELECT BOOL_OR(m.expires_at IS NULL OR m.expires_at > $2) AS has_membership,
				MIN(m.expires_at) FILTER (WHERE m.expires_at IS NULL OR m.expires_at > $2) AS expires_at
			FROM memberships m
			JOIN teams t ON t.id = m.team_id AND t.status = 'active'
			WHERE m.user_id = $1 AND m.team_id = b.team_id
		) membership_exp ON b.team_id IS NOT NULL
		WHERE b.subject_kind = 'user' AND b.subject_id = $1
		  AND (b.expires_at IS NULL OR b.expires_at > $2)
		  AND (b.team_id IS NULL OR COALESCE(membership_exp.has_membership, FALSE))
		ORDER BY b.id`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	return scanAuthzRoleBindings(rows)
}

// ListGroupRoleBindings returns active group bindings inherited by the user's
// active memberships. Team status and binding scope are checked in the same
// query so unrelated tenants never enter the effective set.
func ListGroupRoleBindings(ctx context.Context, q Q, userID string, now time.Time) ([]RoleBinding, error) {
	rows, err := q.Query(ctx, `
		SELECT b.id, COALESCE(b.team_id, m.team_id), b.role_id, b.subject_kind, b.subject_id, b.condition, b.expires_at,
			LEAST(b.expires_at, m.expires_at)
		FROM role_bindings b
		JOIN memberships m ON m.group_id = b.subject_id AND m.user_id = $1
		JOIN teams t ON t.id = m.team_id AND t.status = 'active'
		WHERE b.subject_kind = 'group'
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

// ListTeamRoleBindings returns active team baselines for teams where the user
// has at least one unexpired group membership.
func ListTeamRoleBindings(ctx context.Context, q Q, userID string, now time.Time) ([]RoleBinding, error) {
	rows, err := q.Query(ctx, `
		SELECT b.id, b.team_id, b.role_id, b.subject_kind, b.subject_id, b.condition, b.expires_at,
			LEAST(b.expires_at, membership_exp.expires_at)
		FROM role_bindings b
		JOIN roles r ON r.id = b.role_id AND (r.team_id IS NULL OR r.team_id = b.team_id)
		JOIN teams t ON t.id = b.team_id AND t.status = 'active'
		JOIN LATERAL (
			SELECT COUNT(*) FILTER (WHERE m.expires_at IS NULL OR m.expires_at > $2) AS active_memberships,
				MIN(m.expires_at) FILTER (WHERE m.expires_at IS NULL OR m.expires_at > $2) AS expires_at
			FROM memberships m
			WHERE m.user_id = $1 AND m.team_id = b.team_id
		) membership_exp ON membership_exp.active_memberships > 0
		WHERE b.subject_kind = 'team' AND b.subject_id = b.team_id
		  AND (b.expires_at IS NULL OR b.expires_at > $2)
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

// UserHasIAMPermission reports whether a user's active direct, group, or team
// role bindings grant an effective IAM permission. It intentionally does not
// check users.status so callers can apply their own status policy.
func UserHasIAMPermission(ctx context.Context, q Q, userID string) (bool, error) {
	now := time.Now()
	direct, err := ListDirectRoleBindings(ctx, q, userID, now)
	if err != nil {
		return false, err
	}
	group, err := ListGroupRoleBindings(ctx, q, userID, now)
	if err != nil {
		return false, err
	}
	team, err := ListTeamRoleBindings(ctx, q, userID, now)
	if err != nil {
		return false, err
	}
	bindings := append(direct, group...)
	bindings = append(bindings, team...)
	roleIDs := make([]string, 0, len(bindings))
	seenRoles := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, ok := seenRoles[binding.RoleID]; ok {
			continue
		}
		seenRoles[binding.RoleID] = struct{}{}
		roleIDs = append(roleIDs, binding.RoleID)
	}
	rolePermissions, err := ListRolePermissionsForRoles(ctx, q, roleIDs)
	if err != nil {
		return false, err
	}

	type scope struct {
		teamID string
		isTeam bool
	}
	byScope := make(map[scope][]domain.Permission)
	for _, binding := range bindings {
		if binding.Condition != nil && strings.TrimSpace(*binding.Condition) != "" {
			hasIAMPermission := false
			for _, key := range rolePermissions[binding.RoleID] {
				permission, err := domain.Parse(key)
				if err == nil && (permission.Resource == "iam" || permission.Resource == "*") {
					hasIAMPermission = true
					break
				}
			}
			if !hasIAMPermission {
				continue
			}
			condition, err := domain.Compile(*binding.Condition)
			if err != nil {
				return false, fmt.Errorf("compile IAM binding condition: %w", err)
			}
			values := domain.Context{
				Subject:  domain.Subject{ID: userID, Kind: "user"},
				Request:  domain.Request{Time: now},
			}
			if binding.TeamID != nil {
				values.Resource.TeamID = *binding.TeamID
			}
			allowed, err := condition.EvalWithContext(ctx, values)
			if err != nil {
				return false, fmt.Errorf("evaluate IAM binding condition: %w", err)
			}
			if !allowed {
				continue
			}
		}
		key := scope{}
		if binding.TeamID != nil {
			key.teamID = *binding.TeamID
			key.isTeam = true
		}
		for _, permissionKey := range rolePermissions[binding.RoleID] {
			permission, err := domain.Parse(permissionKey)
			if err != nil {
				continue
			}
			byScope[key] = append(byScope[key], permission)
		}
	}
	for _, permissions := range byScope {
		requests := make([]domain.Permission, 0, len(permissions))
		for _, permission := range permissions {
			if permission.Deny || (permission.Resource != "iam" && permission.Resource != "*") {
				continue
			}
			permission.Resource = "iam"
			requests = append(requests, permission)
		}
		for _, resolution := range domain.Resolve(permissions, requests) {
			if resolution.Allowed {
				return true, nil
			}
		}
	}
	return false, nil
}

// RolePermissionGrant is one effective permission row for admin-plane checks.
// A nil TeamID denotes a platform binding; scoped rows carry their team.
type RolePermissionGrant struct {
	TeamID    *string
	Key       string
	Condition *string
}

// ListEffectiveRolePermissionGrants returns active platform and tenant grants
// for the admin plane without flattening their team scope.
func ListEffectiveRolePermissionGrants(ctx context.Context, q Q, userID string, now time.Time) ([]RolePermissionGrant, error) {
	rows, err := q.Query(ctx, `
		WITH applicable_bindings AS (
			SELECT b.role_id, b.team_id, b.condition
			FROM role_bindings b
			WHERE b.subject_kind = 'user' AND b.subject_id = $1
			  AND (b.expires_at IS NULL OR b.expires_at > $2)
			  AND (
				b.team_id IS NULL OR EXISTS (
					SELECT 1
					FROM memberships m
					JOIN teams t ON t.id = m.team_id AND t.status = 'active'
					WHERE m.user_id = $1 AND m.team_id = b.team_id
					  AND (m.expires_at IS NULL OR m.expires_at > $2)
				)
			  )
			UNION ALL
			SELECT b.role_id, COALESCE(b.team_id, m.team_id), b.condition
			FROM role_bindings b
			JOIN memberships m ON m.group_id = b.subject_id AND m.user_id = $1
			JOIN teams t ON t.id = m.team_id AND t.status = 'active'
			WHERE b.subject_kind = 'group'
			  AND (m.expires_at IS NULL OR m.expires_at > $2)
			  AND (b.expires_at IS NULL OR b.expires_at > $2)
			  AND (b.team_id IS NULL OR b.team_id = m.team_id)
			UNION ALL
			SELECT b.role_id, b.team_id, b.condition
			FROM role_bindings b
			JOIN roles r ON r.id = b.role_id AND (r.team_id IS NULL OR r.team_id = b.team_id)
			JOIN teams t ON t.id = b.team_id AND t.status = 'active'
			WHERE b.subject_kind = 'team' AND b.subject_id = b.team_id
			  AND (b.expires_at IS NULL OR b.expires_at > $2)
			  AND EXISTS (
				SELECT 1
				FROM memberships m
				WHERE m.user_id = $1 AND m.team_id = b.team_id
				  AND (m.expires_at IS NULL OR m.expires_at > $2)
			  )
		)
		SELECT DISTINCT b.team_id, rp.permission_key, b.condition
		FROM applicable_bindings b
		JOIN role_permissions rp ON rp.role_id = b.role_id
		ORDER BY b.team_id NULLS FIRST, rp.permission_key, b.condition`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	grants := make([]RolePermissionGrant, 0)
	for rows.Next() {
		var grant RolePermissionGrant
		var teamID, condition pgtype.Text
		if err := rows.Scan(&teamID, &grant.Key, &condition); err != nil {
			return nil, err
		}
		grant.TeamID = textPointer(teamID)
		grant.Condition = textPointer(condition)
		grants = append(grants, grant)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return grants, nil
}
func scanAuthzRoleBindings(rows pgx.Rows) ([]RoleBinding, error) {
	bindings := make([]RoleBinding, 0)
	for rows.Next() {
		var binding RoleBinding
		var teamID, condition pgtype.Text
		if err := rows.Scan(
			&binding.ID, &teamID, &binding.RoleID, &binding.SubjectKind,
			&binding.SubjectID, &condition, &binding.ExpiresAt, &binding.EffectiveUntil,
		); err != nil {
			return nil, err
		}
		binding.TeamID = textPointer(teamID)
		binding.Condition = textPointer(condition)
		bindings = append(bindings, binding)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return bindings, nil
}
