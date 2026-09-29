package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func CreatePasswordPolicy(ctx context.Context, q Q, policy PasswordPolicy) (PasswordPolicy, error) {
	if policy.ID == "" {
		policy.ID = NewID()
	}
	return scanPasswordPolicy(q.QueryRow(ctx, `
		INSERT INTO password_policies (
			id, name, priority, subject_kind, subject_id, min_length,
			require_letter, require_upper, require_lower, require_digit, require_symbol
		)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
		RETURNING id, name, priority, subject_kind, subject_id, min_length,
			require_letter, require_upper, require_lower, require_digit, require_symbol,
			created_at, updated_at`,
		policy.ID, policy.Name, policy.Priority, policy.SubjectKind, policy.SubjectID,
		policy.MinLength, policy.RequireLetter, policy.RequireUpper, policy.RequireLower,
		policy.RequireDigit, policy.RequireSymbol))
}

func GetPasswordPolicy(ctx context.Context, q Q, id string) (PasswordPolicy, error) {
	return scanPasswordPolicy(q.QueryRow(ctx, `
		SELECT id, name, priority, subject_kind, subject_id, min_length,
			require_letter, require_upper, require_lower, require_digit, require_symbol,
			created_at, updated_at
		FROM password_policies WHERE id = $1`, id))
}
func GetPasswordPolicyForUpdate(ctx context.Context, q Q, id string) (PasswordPolicy, error) {
	return scanPasswordPolicy(q.QueryRow(ctx, `
		SELECT id, name, priority, subject_kind, subject_id, min_length,
			require_letter, require_upper, require_lower, require_digit, require_symbol,
			created_at, updated_at
		FROM password_policies WHERE id = $1 FOR UPDATE`, id))
}

func ListPasswordPolicies(ctx context.Context, q Q, cursor string, limit int) ([]PasswordPolicy, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT id, name, priority, subject_kind, subject_id, min_length,
				require_letter, require_upper, require_lower, require_digit, require_symbol,
				created_at, updated_at
			FROM password_policies ORDER BY id LIMIT $1`, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, name, priority, subject_kind, subject_id, min_length,
				require_letter, require_upper, require_lower, require_digit, require_symbol,
				created_at, updated_at
			FROM password_policies WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	policies := make([]PasswordPolicy, 0, limit)
	for rows.Next() {
		policy, err := scanPasswordPolicy(rows)
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

func UpdatePasswordPolicy(ctx context.Context, q Q, policy PasswordPolicy) (PasswordPolicy, error) {
	return scanPasswordPolicy(q.QueryRow(ctx, `
		UPDATE password_policies
		SET name = $2, priority = $3, subject_kind = $4, subject_id = $5,
			min_length = $6, require_letter = $7, require_upper = $8,
			require_lower = $9, require_digit = $10, require_symbol = $11,
			updated_at = now()
		WHERE id = $1
		RETURNING id, name, priority, subject_kind, subject_id, min_length,
			require_letter, require_upper, require_lower, require_digit, require_symbol,
			created_at, updated_at`,
		policy.ID, policy.Name, policy.Priority, policy.SubjectKind, policy.SubjectID,
		policy.MinLength, policy.RequireLetter, policy.RequireUpper, policy.RequireLower,
		policy.RequireDigit, policy.RequireSymbol))
}

func DeletePasswordPolicy(ctx context.Context, q Q, id string) error {
	var deletedID string
	return q.QueryRow(ctx, `DELETE FROM password_policies WHERE id = $1 RETURNING id`, id).Scan(&deletedID)
}

func DeletePasswordPoliciesForSubject(ctx context.Context, q Q, subjectKind, subjectID string) error {
	_, err := q.Exec(ctx, `
		DELETE FROM password_policies
		WHERE subject_kind = $1 AND subject_id = $2`, subjectKind, subjectID)
	return err
}

// ListEffectivePasswordPolicies returns active policies matching the user
// directly, through active memberships, or through active unconditional role
// bindings. Conditional role bindings do not count as holding the role.
func ListEffectivePasswordPolicies(ctx context.Context, q Q, userID string, now time.Time) ([]PasswordPolicy, error) {
	rows, err := q.Query(ctx, `
		WITH effective_roles AS (
			SELECT rb.role_id
			FROM role_bindings rb
			WHERE rb.subject_kind = 'user'
			  AND rb.subject_id = $1
			  AND (rb.expires_at IS NULL OR rb.expires_at > $2)
			  AND (rb.condition IS NULL OR btrim(rb.condition) = '')
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
			SELECT rb.role_id
			FROM role_bindings rb
			JOIN memberships m ON m.group_id = rb.subject_id
			WHERE rb.subject_kind = 'group'
			  AND m.user_id = $1
			  AND (m.expires_at IS NULL OR m.expires_at > $2)
			  AND (rb.expires_at IS NULL OR rb.expires_at > $2)
			  AND (rb.condition IS NULL OR btrim(rb.condition) = '')
			  AND (rb.team_id IS NULL OR rb.team_id = m.team_id)
		)
		SELECT p.id, p.name, p.priority, p.subject_kind, p.subject_id, p.min_length,
			p.require_letter, p.require_upper, p.require_lower, p.require_digit, p.require_symbol,
			p.created_at, p.updated_at
		FROM password_policies p
		WHERE (p.subject_kind = 'user' AND p.subject_id = $1)
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
				WHERE er.role_id = p.subject_id
			))
		ORDER BY p.priority DESC, p.id ASC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	policies := make([]PasswordPolicy, 0)
	for rows.Next() {
		policy, err := scanPasswordPolicy(rows)
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

func scanPasswordPolicy(row pgx.Row) (PasswordPolicy, error) {
	var policy PasswordPolicy
	var minLength pgtype.Int4
	var requireLetter, requireUpper, requireLower, requireDigit, requireSymbol pgtype.Bool
	if err := row.Scan(
		&policy.ID, &policy.Name, &policy.Priority, &policy.SubjectKind, &policy.SubjectID,
		&minLength, &requireLetter, &requireUpper, &requireLower, &requireDigit, &requireSymbol,
		&policy.CreatedAt, &policy.UpdatedAt,
	); err != nil {
		return PasswordPolicy{}, err
	}
	if minLength.Valid {
		value := int(minLength.Int32)
		policy.MinLength = &value
	}
	policy.RequireLetter = passwordPolicyBoolPointer(requireLetter)
	policy.RequireUpper = passwordPolicyBoolPointer(requireUpper)
	policy.RequireLower = passwordPolicyBoolPointer(requireLower)
	policy.RequireDigit = passwordPolicyBoolPointer(requireDigit)
	policy.RequireSymbol = passwordPolicyBoolPointer(requireSymbol)
	return policy, nil
}

func passwordPolicyBoolPointer(value pgtype.Bool) *bool {
	if !value.Valid {
		return nil
	}
	result := value.Bool
	return &result
}
