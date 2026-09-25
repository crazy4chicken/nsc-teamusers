package store

import (
	"context"
	"fmt"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// GetUserByUsername loads the identity used by password and service logins.
func GetUserByUsername(ctx context.Context, q Q, username string) (User, error) {
	return GetUserForAuth(ctx, q, username)
}

// GetUserByEmail loads the identity used by password recovery requests.
func GetUserByEmail(ctx context.Context, q Q, email string) (User, error) {
	return scanUser(q.QueryRow(ctx, `
        SELECT id, username, email, display_name, status, perm_ver, failed_logins, locked_until, email_verified_at, approved_at, approved_by, created_at, updated_at
        FROM users WHERE email = $1`, email))
}

// IsEmailTaken reports whether another user already owns the case-insensitive
// email address. The excluded user ID is allowed to retain its current value.
func IsEmailTaken(ctx context.Context, q Q, email, excludedUserID string) (bool, error) {
	var taken bool
	err := q.QueryRow(ctx, `
		SELECT EXISTS (
			SELECT 1 FROM users
			WHERE email = $1 AND ($2 = '' OR id <> $2)
		)`, email, excludedUserID).Scan(&taken)
	return taken, err
}

// GetUserForAuth loads the identity and lockout state used by an authentication
// attempt. Lockout columns are returned with the same user projection as the
// regular user helpers.
func GetUserForAuth(ctx context.Context, q Q, username string) (User, error) {
	return scanUser(q.QueryRow(ctx, `
		SELECT id, username, email, display_name, status, perm_ver, failed_logins, locked_until, email_verified_at, approved_at, approved_by, created_at, updated_at
		FROM users WHERE username = $1`, username))
}

// IncrementFailedLogins increments the counter and locks the account at the
// configured threshold in one UPDATE. The duration is passed as a PostgreSQL
// interval string so pgx does not need to infer a time.Duration OID.
func IncrementFailedLogins(ctx context.Context, q Q, userID string, threshold int, duration time.Duration) (bool, error) {
	if threshold < 1 {
		threshold = 1
	}
	interval := fmt.Sprintf("%.9f seconds", duration.Seconds())
	var failed int
	var lockedUntil pgtype.Timestamptz
	err := q.QueryRow(ctx, `
		UPDATE users
		SET failed_logins = failed_logins + 1,
		    locked_until = CASE
		        WHEN failed_logins + 1 >= $2 THEN now() + $3::interval
		        ELSE locked_until
		    END,
		    updated_at = now()
		WHERE id = $1
		RETURNING failed_logins, locked_until`, userID, threshold, interval).Scan(&failed, &lockedUntil)
	if err != nil {
		return false, err
	}
	return failed >= threshold && lockedUntil.Valid, nil
}

// ResetFailedLogins clears the lockout state after a successful login or an
// administrative disable operation.
func ResetFailedLogins(ctx context.Context, q Q, userID string) error {
	_, err := q.Exec(ctx, `
		UPDATE users
		SET failed_logins = 0, locked_until = NULL, updated_at = now()
		WHERE id = $1`, userID)
	return err
}

// GetLockState returns the current failure counter and lock deadline.
func GetLockState(ctx context.Context, q Q, userID string) (int, *time.Time, error) {
	var failed int
	var lockedUntil pgtype.Timestamptz
	err := q.QueryRow(ctx, `SELECT failed_logins, locked_until FROM users WHERE id = $1`, userID).Scan(&failed, &lockedUntil)
	if err != nil {
		return 0, nil, err
	}
	if !lockedUntil.Valid {
		return failed, nil, nil
	}
	value := lockedUntil.Time
	return failed, &value, nil
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
		SELECT id, user_id, family_id, client_meta, created_at, expires_at, family_not_after, revoked_at, revoke_reason
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
