package store

import (
	"context"
	"errors"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
)

var (
	ErrOIDCEmailAmbiguous = errors.New("OIDC email matches multiple users")
	ErrOIDCLinkRefused   = errors.New("OIDC email cannot be linked to this user")
)

// LockOIDCLogin serializes resolution by issuer/subject and, when present, by
// case-insensitive email. Call it inside the transaction that links identity.
func LockOIDCLogin(ctx context.Context, q Q, issuer, subject, email string) error {
	if _, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "oidc\x00"+issuer+"\x00"+subject); err != nil {
		return err
	}
	if email == "" {
		return nil
	}
	_, err := q.Exec(ctx, `SELECT pg_advisory_xact_lock(hashtextextended($1, 0))`, "email\x00"+strings.ToLower(email))
	return err
}

// CreateOIDCLoginState stores one-time state and nonce digests with PKCE data.
func CreateOIDCLoginState(ctx context.Context, q Q, stateHash, nonceHash, codeChallenge, codeVerifier string, expiresAt, now time.Time) error {
	if _, err := q.Exec(ctx, `
		WITH expired AS (
			SELECT state_hash FROM oidc_login_states
			WHERE expires_at <= $1
			ORDER BY expires_at
			LIMIT 100
		)
		DELETE FROM oidc_login_states AS states
		USING expired
		WHERE states.state_hash = expired.state_hash`, now); err != nil {
		return err
	}
	var inserted string
	return q.QueryRow(ctx, `
		INSERT INTO oidc_login_states (state_hash, nonce_hash, code_challenge, code_verifier, expires_at)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING state_hash`, stateHash, nonceHash, codeChallenge, codeVerifier, expiresAt).Scan(&inserted)
}

// ConsumeOIDCLoginState atomically deletes an unexpired state and returns its
// nonce digest and PKCE data. Missing, expired, and reused values are indistinguishable.
func ConsumeOIDCLoginState(ctx context.Context, q Q, stateHash string, now time.Time) (string, string, string, error) {
	var nonceHash, codeChallenge, codeVerifier string
	err := q.QueryRow(ctx, `
		DELETE FROM oidc_login_states
		WHERE state_hash = $1 AND expires_at > $2
		RETURNING nonce_hash, code_challenge, code_verifier`, stateHash, now).Scan(&nonceHash, &codeChallenge, &codeVerifier)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", "", ErrNotFound
	}
	return nonceHash, codeChallenge, codeVerifier, err
}

// GetOIDCIdentity resolves an external issuer/subject pair to its local user.
func GetOIDCIdentity(ctx context.Context, q Q, issuer, subject string) (string, error) {
	var userID string
	err := q.QueryRow(ctx, `
		SELECT user_id FROM oidc_identities
		WHERE issuer = $1 AND sub = $2`, issuer, subject).Scan(&userID)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", ErrNotFound
	}
	return userID, err
}

// CreateOIDCIdentity links an issuer/subject pair without replacing an
// existing mapping. It returns the user already associated with a race winner.
func CreateOIDCIdentity(ctx context.Context, q Q, userID, issuer, subject string) (string, error) {
	var linkedUserID string
	err := q.QueryRow(ctx, `
		INSERT INTO oidc_identities (user_id, issuer, sub)
		VALUES ($1, $2, $3)
		ON CONFLICT (issuer, sub) DO NOTHING
		RETURNING user_id`, userID, issuer, subject).Scan(&linkedUserID)
	if errors.Is(err, pgx.ErrNoRows) {
		return GetOIDCIdentity(ctx, q, issuer, subject)
	}
	return linkedUserID, err
}

// GetOIDCUserByEmail returns the unique case-insensitive email match, failing
// closed when legacy data contains more than one matching account.
func GetOIDCUserByEmail(ctx context.Context, q Q, email string) (User, error) {
	rows, err := q.Query(ctx, `
		SELECT id, username, email, display_name, status, perm_ver, failed_logins,
		       locked_until, email_verified_at, approved_at, approved_by, created_at, updated_at
		FROM users
		WHERE email = $1
		ORDER BY id
		LIMIT 2`, email)
	if err != nil {
		return User{}, err
	}
	defer rows.Close()
	if !rows.Next() {
		if err := rows.Err(); err != nil {
			return User{}, err
		}
		return User{}, pgx.ErrNoRows
	}
	user, err := scanUser(rows)
	if err != nil {
		return User{}, err
	}
	if rows.Next() {
		return User{}, ErrOIDCEmailAmbiguous
	}
	if err := rows.Err(); err != nil {
		return User{}, err
	}
	if user.EmailVerifiedAt == nil || user.Status == "pending" || user.Status == "invited" || isErasedOIDCUser(user) {
		return User{}, ErrOIDCLinkRefused
	}
	return user, nil
}

func isErasedOIDCUser(user User) bool {
	return user.Status == "disabled" && strings.HasPrefix(user.Username, "deleted_") && user.Email != nil &&
		strings.EqualFold(*user.Email, user.Username+"@deleted.invalid")
}

// DeleteOIDCIdentitiesForUser removes every external identity linked to a user.
func DeleteOIDCIdentitiesForUser(ctx context.Context, q Q, userID string) error {
	_, err := q.Exec(ctx, `DELETE FROM oidc_identities WHERE user_id = $1`, userID)
	return err
}

// ClearUserExternalID removes the SCIM external identifier linked to a user.
func ClearUserExternalID(ctx context.Context, q Q, userID string) error {
	_, err := q.Exec(ctx, `UPDATE users SET external_id = NULL, updated_at = now() WHERE id = $1`, userID)
	return err
}
