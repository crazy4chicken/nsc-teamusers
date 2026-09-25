package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// ErrNotFound indicates that a requested lifecycle record does not exist or is
// no longer eligible for the requested operation.
var ErrNotFound = errors.New("not found")

// VerificationToken mirrors the verification_tokens table.
type VerificationToken struct {
	ID        string          `json:"id"`
	UserID    string          `json:"user_id"`
	Kind      string          `json:"kind"`
	TokenHash string          `json:"-"`
	Payload   json.RawMessage `json:"payload,omitempty"`
	ExpiresAt time.Time       `json:"expires_at"`
	UsedAt    *time.Time      `json:"used_at,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
}

// CreateVerificationToken stores a one-time verification token. The token ID
// is always an application-generated ULID when the caller does not supply one.
func CreateVerificationToken(ctx context.Context, q Q, token VerificationToken) (VerificationToken, error) {
	if token.ID == "" {
		token.ID = NewID()
	}
	return scanVerificationToken(q.QueryRow(ctx, `
		INSERT INTO verification_tokens (id, user_id, kind, token_hash, expires_at, used_at, payload)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING id, user_id, kind, token_hash, expires_at, used_at, created_at, payload`,
		token.ID, token.UserID, token.Kind, token.TokenHash, token.ExpiresAt, token.UsedAt, token.Payload))
}

// ConsumeVerificationToken atomically marks an unexpired token as used and
// returns its owning user and token kind. Expired, used, or unknown tokens all
// return ErrNotFound so callers cannot distinguish those cases.
func ConsumeVerificationToken(ctx context.Context, q Q, tokenHash string) (string, string, error) {
	userID, kind, _, err := ConsumeVerificationTokenWithPayload(ctx, q, tokenHash)
	return userID, kind, err
}

// ConsumeVerificationTokenWithPayload is the payload-aware form used by
// invitation and other lifecycle flows that bind additional data to a token.
// The mark-used update remains atomic and preserves the same generic not-found
// behavior as ConsumeVerificationToken.
func ConsumeVerificationTokenWithPayload(ctx context.Context, q Q, tokenHash string) (string, string, json.RawMessage, error) {
	var userID, kind string
	var payload []byte
	err := q.QueryRow(ctx, `
		UPDATE verification_tokens
		SET used_at = now()
		WHERE token_hash = $1 AND used_at IS NULL AND expires_at > now()
		RETURNING user_id, kind, payload`, tokenHash).Scan(&userID, &kind, &payload)
	if errors.Is(err, pgx.ErrNoRows) {
		return "", "", nil, ErrNotFound
	}
	if err != nil {
		return "", "", nil, err
	}
	return userID, kind, json.RawMessage(payload), nil
}

// SetEmailVerified records the successful verification timestamp.
func SetEmailVerified(ctx context.Context, q Q, userID string, at time.Time) error {
	_, err := q.Exec(ctx, `
		UPDATE users
		SET email_verified_at = $2, updated_at = now()
		WHERE id = $1`, userID, at)
	return err
}

// ActivateInvitedUser transitions an invited user to active and records the
// invitation acceptance timestamp. A nil display name preserves the existing
// value while a non-nil value replaces it.
func ActivateInvitedUser(ctx context.Context, q Q, userID string, displayName *string, at time.Time) (User, error) {
	return scanUser(q.QueryRow(ctx, `
		UPDATE users
		SET status = 'active', email_verified_at = $2,
			display_name = COALESCE($3::text, display_name), updated_at = now()
		WHERE id = $1 AND status = 'invited'
		RETURNING id, username, email, display_name, status, perm_ver, failed_logins, locked_until, email_verified_at, approved_at, approved_by, created_at, updated_at`,
		userID, at, displayName))
}

// ApproveUser transitions a user to active and records the approving subject.
func ApproveUser(ctx context.Context, q Q, userID, approverID string, at time.Time) (User, error) {
	user, err := scanUser(q.QueryRow(ctx, `
		UPDATE users
		SET status = 'active', approved_at = $3, approved_by = $2, updated_at = now()
		WHERE id = $1 AND email_verified_at IS NOT NULL
		RETURNING id, username, email, display_name, status, perm_ver, failed_logins, locked_until, email_verified_at, approved_at, approved_by, created_at, updated_at`,
		userID, approverID, at))
	if errors.Is(err, pgx.ErrNoRows) {
		return User{}, ErrNotFound
	}
	return user, err
}

func scanVerificationToken(row pgx.Row) (VerificationToken, error) {
	var token VerificationToken
	var usedAt pgtype.Timestamptz
	var payload []byte
	if err := row.Scan(
		&token.ID, &token.UserID, &token.Kind, &token.TokenHash,
		&token.ExpiresAt, &usedAt, &token.CreatedAt, &payload,
	); err != nil {
		return VerificationToken{}, err
	}
	if usedAt.Valid {
		value := usedAt.Time
		token.UsedAt = &value
	}
	if payload != nil {
		token.Payload = json.RawMessage(payload)
	}
	return token, nil
}
