package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ListEffectiveSessionPolicies returns policies matching the user through
// active memberships or active unconditional role bindings, ordered by priority.
func ListEffectiveSessionPolicies(ctx context.Context, q Q, userID string, now time.Time) ([]SessionPolicy, error) {
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
		SELECT p.id, p.name, p.priority, p.subject_kind, p.subject_id,
			p.max_concurrent_sessions, p.idle_timeout_minutes, p.created_at, p.updated_at
		FROM session_policies p
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
				WHERE er.role_id = p.subject_id
			))
		ORDER BY p.priority DESC, p.id ASC`, userID, now)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	policies := make([]SessionPolicy, 0)
	for rows.Next() {
		policy, err := scanSessionPolicy(rows)
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

// ResolveSessionPolicy resolves each configured field from the highest-priority
// matching policy that sets it.
func ResolveSessionPolicy(ctx context.Context, q Q, userID string, now time.Time) (SessionPolicy, error) {
	policies, err := ListEffectiveSessionPolicies(ctx, q, userID, now)
	if err != nil {
		return SessionPolicy{}, err
	}
	if len(policies) == 0 {
		return SessionPolicy{}, nil
	}

	resolved := policies[0]
	resolved.MaxConcurrentSessions = nil
	resolved.IdleTimeoutMinutes = nil
	for i := range policies {
		if resolved.MaxConcurrentSessions == nil && policies[i].MaxConcurrentSessions != nil {
			resolved.MaxConcurrentSessions = policies[i].MaxConcurrentSessions
		}
		if resolved.IdleTimeoutMinutes == nil && policies[i].IdleTimeoutMinutes != nil {
			resolved.IdleTimeoutMinutes = policies[i].IdleTimeoutMinutes
		}
		if resolved.MaxConcurrentSessions != nil && resolved.IdleTimeoutMinutes != nil {
			break
		}
	}
	return resolved, nil
}

// DeleteSessionPoliciesForSubject removes policies attached to a deleted subject.
func DeleteSessionPoliciesForSubject(ctx context.Context, q Q, subjectKind, subjectID string) error {
	_, err := q.Exec(ctx, `DELETE FROM session_policies WHERE subject_kind = $1 AND subject_id = $2`, subjectKind, subjectID)
	return err
}

// GetSessionUserID reads a refresh session owner without locking its row. A
// caller that needs both locks must lock the user before the session row.
func GetSessionUserID(ctx context.Context, q Q, sessionID string) (string, error) {
	var userID string
	err := q.QueryRow(ctx, `SELECT user_id FROM sessions WHERE id = $1`, sessionID).Scan(&userID)
	return userID, err
}

// LockSessionPolicyUser acquires the user row lock used by session governance.
func LockSessionPolicyUser(ctx context.Context, q Q, userID string) error {
	var lockedUserID string
	return q.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&lockedUserID)
}

// EnforceConcurrentSessionLimit evicts the oldest active sessions needed to
// make room for the new session. replacingSessionID is excluded during refresh
// rotation because that session is revoked when the replacement is created.
// The user row is locked before any session rows to match refresh rotation.
func EnforceConcurrentSessionLimit(ctx context.Context, q Q, userID string, maxSessions *int, replacingSessionID string, now time.Time) error {

	if maxSessions == nil {
		return nil
	}

	if err := LockSessionPolicyUser(ctx, q, userID); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		WITH active_count AS (
			SELECT COUNT(*) AS count
			FROM sessions
			WHERE user_id = $1
			  AND revoked_at IS NULL
			  AND expires_at > $2
			  AND id <> $4
		), victims AS (
			SELECT s.id
			FROM sessions s
			WHERE s.user_id = $1
			  AND s.revoked_at IS NULL
			  AND s.expires_at > $2
			  AND s.id <> $4
			ORDER BY s.created_at ASC, s.id ASC
			LIMIT (
				SELECT GREATEST(c.count - $3::bigint + 1, 0)
				FROM active_count c
			)
		)
		UPDATE sessions AS s
		SET revoked_at = $2, revoke_reason = 'evicted_by_policy'
		FROM victims
		WHERE s.id = victims.id AND s.revoked_at IS NULL`,
		userID, now, *maxSessions, replacingSessionID)
	return err
}

// TouchSession records successful refresh activity on the presented session.
func TouchSession(ctx context.Context, q Q, sessionID string, now time.Time) error {
	result, err := q.Exec(ctx, `
		UPDATE sessions
		SET last_active_at = GREATEST(last_active_at, $2)
		WHERE id = $1 AND revoked_at IS NULL`, sessionID, now)
	if err != nil {
		return err
	}
	if result.RowsAffected() == 0 {
		return ErrNotFound
	}
	return nil
}

func scanSessionPolicy(row pgx.Row) (SessionPolicy, error) {
	var policy SessionPolicy
	var maxSessions, idleTimeout pgtype.Int4
	if err := row.Scan(
		&policy.ID, &policy.Name, &policy.Priority, &policy.SubjectKind, &policy.SubjectID,
		&maxSessions, &idleTimeout, &policy.CreatedAt, &policy.UpdatedAt,
	); err != nil {
		return SessionPolicy{}, err
	}
	if maxSessions.Valid {
		value := int(maxSessions.Int32)
		policy.MaxConcurrentSessions = &value
	}
	if idleTimeout.Valid {
		value := int(idleTimeout.Int32)
		policy.IdleTimeoutMinutes = &value
	}
	return policy, nil
}
