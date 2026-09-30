package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
)

func CreateMFAPolicy(ctx context.Context, q Q, policy MFAPolicy) (MFAPolicy, error) {
	if policy.ID == "" {
		policy.ID = NewID()
	}
	return scanMFAPolicy(q.QueryRow(ctx, `
		INSERT INTO mfa_policies (id, name, priority, subject_kind, subject_id, required, deny_unenrolled)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, name, priority, subject_kind, subject_id, required, deny_unenrolled, created_at, updated_at`,
		policy.ID, policy.Name, policy.Priority, policy.SubjectKind, policy.SubjectID, policy.Required, policy.DenyUnenrolled))
}

func GetMFAPolicy(ctx context.Context, q Q, id string) (MFAPolicy, error) {
	return scanMFAPolicy(q.QueryRow(ctx, `
		SELECT id, name, priority, subject_kind, subject_id, required, deny_unenrolled, created_at, updated_at
		FROM mfa_policies WHERE id = $1`, id))
}

func GetMFAPolicyForUpdate(ctx context.Context, q Q, id string) (MFAPolicy, error) {
	return scanMFAPolicy(q.QueryRow(ctx, `
		SELECT id, name, priority, subject_kind, subject_id, required, deny_unenrolled, created_at, updated_at
		FROM mfa_policies WHERE id = $1 FOR UPDATE`, id))
}

func ListMFAPolicies(ctx context.Context, q Q, cursor string, limit int) ([]MFAPolicy, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT id, name, priority, subject_kind, subject_id, required, deny_unenrolled, created_at, updated_at
			FROM mfa_policies ORDER BY id LIMIT $1`, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, name, priority, subject_kind, subject_id, required, deny_unenrolled, created_at, updated_at
			FROM mfa_policies WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	policies := make([]MFAPolicy, 0, limit)
	for rows.Next() {
		policy, err := scanMFAPolicy(rows)
		if err != nil {
			return nil, "", err
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return policies, nextCursor(len(policies), limit, func(i int) string { return policies[i].ID }), nil
}

func UpdateMFAPolicy(ctx context.Context, q Q, policy MFAPolicy) (MFAPolicy, error) {
	return scanMFAPolicy(q.QueryRow(ctx, `
		UPDATE mfa_policies
		SET name = $2, priority = $3, subject_kind = $4, subject_id = $5,
			required = $6, deny_unenrolled = $7, updated_at = now()
		WHERE id = $1
		RETURNING id, name, priority, subject_kind, subject_id, required, deny_unenrolled, created_at, updated_at`,
		policy.ID, policy.Name, policy.Priority, policy.SubjectKind, policy.SubjectID, policy.Required, policy.DenyUnenrolled))
}

func DeleteMFAPolicy(ctx context.Context, q Q, id string) error {
	var deletedID string
	return q.QueryRow(ctx, `DELETE FROM mfa_policies WHERE id = $1 RETURNING id`, id).Scan(&deletedID)
}

// DeleteMFAPoliciesForSubject removes policies attached to a deleted subject.
func DeleteMFAPoliciesForSubject(ctx context.Context, q Q, subjectKind, subjectID string) error {
	_, err := q.Exec(ctx, `DELETE FROM mfa_policies WHERE subject_kind = $1 AND subject_id = $2`, subjectKind, subjectID)
	return err
}

// ListEffectiveMFAPolicies returns policies matching the user through active
// team, group, or role memberships. Conditional role bindings count only for
// required policies, which errs on the side of stronger authentication.
func ListEffectiveMFAPolicies(ctx context.Context, q Q, userID string, now time.Time) ([]MFAPolicy, error) {
	rows, err := q.Query(ctx, `
		WITH effective_roles AS (
			SELECT rb.role_id, (rb.condition IS NULL OR btrim(rb.condition) = '') AS unconditional
			FROM role_bindings rb
			WHERE rb.subject_kind = 'user'
			  AND rb.subject_id = $1
			  AND (rb.expires_at IS NULL OR rb.expires_at > $2)
			  AND (
				rb.team_id IS NULL
				OR EXISTS (
					SELECT 1
					FROM memberships m
					WHERE m.user_id = $1
					  AND m.team_id = rb.team_id
					  AND (m.expires_at IS NULL OR m.expires_at > $2)
				)
			  )
			UNION
			SELECT rb.role_id, (rb.condition IS NULL OR btrim(rb.condition) = '') AS unconditional
			FROM role_bindings rb
			JOIN memberships m ON m.group_id = rb.subject_id
			WHERE rb.subject_kind = 'group'
			  AND m.user_id = $1
			  AND (m.expires_at IS NULL OR m.expires_at > $2)
			  AND (rb.expires_at IS NULL OR rb.expires_at > $2)
			  AND (rb.team_id IS NULL OR rb.team_id = m.team_id)
		)
		SELECT p.id, p.name, p.priority, p.subject_kind, p.subject_id, p.required, p.deny_unenrolled, p.created_at, p.updated_at
		FROM mfa_policies p
		WHERE p.subject_kind = 'default'
		   OR (p.subject_kind = 'team' AND EXISTS (
				SELECT 1
				FROM memberships m
				WHERE m.user_id = $1
				  AND m.team_id = p.subject_id
				  AND (m.expires_at IS NULL OR m.expires_at > $2)
			))
		   OR (p.subject_kind = 'group' AND EXISTS (
				SELECT 1
				FROM memberships m
				WHERE m.user_id = $1
				  AND m.group_id = p.subject_id
				  AND (m.expires_at IS NULL OR m.expires_at > $2)
			))
		   OR (p.subject_kind = 'role' AND EXISTS (
				SELECT 1
				FROM effective_roles er
				WHERE er.role_id = p.subject_id AND (p.required OR er.unconditional)
			))
		ORDER BY p.priority DESC, p.id ASC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]MFAPolicy, 0)
	for rows.Next() {
		policy, err := scanMFAPolicy(rows)
		if err != nil {
			return nil, err
		}
		policies = append(policies, policy)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return policies, nil
}

// ResolveMFAPolicy returns the highest-priority effective policy, or a zero
// value when no policy applies.
func ResolveMFAPolicy(ctx context.Context, q Q, userID string, now time.Time) (MFAPolicy, error) {
	policies, err := ListEffectiveMFAPolicies(ctx, q, userID, now)
	if err != nil {
		return MFAPolicy{}, err
	}
	if len(policies) == 0 {
		return MFAPolicy{}, nil
	}
	return policies[0], nil
}

func scanMFAPolicy(row pgx.Row) (MFAPolicy, error) {
	var policy MFAPolicy
	if err := row.Scan(
		&policy.ID, &policy.Name, &policy.Priority, &policy.SubjectKind, &policy.SubjectID,
		&policy.Required, &policy.DenyUnenrolled, &policy.CreatedAt, &policy.UpdatedAt,
	); err != nil {
		return MFAPolicy{}, err
	}
	return policy, nil
}
