package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

// GetUserByUsername loads the identity used by password and service logins.
func GetUserByUsername(ctx context.Context, q Q, username string) (User, error) {
	return scanUser(q.QueryRow(ctx, `
        SELECT id, username, email, display_name, status, perm_ver, email_verified_at, approved_at, approved_by, created_at, updated_at
        FROM users WHERE username = $1`, username))
}

// GetUserTeamID returns a stable active team for token issuance. Users may be
// members of multiple teams; the lexicographically first active team keeps the
// claim deterministic until an explicit team-selection flow exists.
func GetUserTeamID(ctx context.Context, q Q, userID string) (string, error) {
	var teamID string
	err := q.QueryRow(ctx, `
		SELECT m.team_id
		FROM memberships AS m
		JOIN teams AS t ON t.id = m.team_id
		WHERE m.user_id = $1 AND t.status = 'active'
		ORDER BY m.team_id
		LIMIT 1`, userID).Scan(&teamID)
	if err == pgx.ErrNoRows {
		return "", nil
	}
	return teamID, err
}

// GetSessionForUpdate locks a refresh-token row for rotation. The session id
// is the SHA-256 digest of the opaque refresh token; plaintext tokens never
// enter the database.
func GetSessionForUpdate(ctx context.Context, q Q, refreshHash string) (Session, error) {
	return scanSession(q.QueryRow(ctx, `
		SELECT id, user_id, family_id, client_meta, expires_at, family_not_after, revoked_at, revoke_reason
		FROM sessions WHERE id = $1 FOR UPDATE`, refreshHash))
}

// RevokeSession marks one rotated or otherwise invalidated refresh token.
func RevokeSession(ctx context.Context, q Q, id, reason string) error {
	_, err := q.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = $2
		WHERE id = $1 AND revoked_at IS NULL`, id, reason)
	return err
}

// RevokeSessionFamilyReuse marks every session in a family after a rotated
// refresh token is presented again, including rows already revoked for
// rotation. This preserves the theft-detection reason across the family.
func RevokeSessionFamilyReuse(ctx context.Context, q Q, familyID string) error {
	_, err := q.Exec(ctx, `
        UPDATE sessions
        SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'reuse_detected'
        WHERE family_id = $1`, familyID)
	return err
}
