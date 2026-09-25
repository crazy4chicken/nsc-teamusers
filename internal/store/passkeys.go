package store

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// PasskeyCredentialKind is the credentials row kind used for serialized
// WebAuthn credentials.
const PasskeyCredentialKind = "passkeys"

// WebauthnChallenge mirrors the short-lived server-side ceremony state.
type WebauthnChallenge struct {
	ID          string
	UserID      *string
	Kind        string
	Challenge   string
	SessionData json.RawMessage
	ExpiresAt   time.Time
	CreatedAt   time.Time
}

// GetPasskeys loads all WebAuthn credentials owned by a user. The empty set is
// returned when the user has not enrolled a passkey.
func GetPasskeys(ctx context.Context, q Q, userID string) ([]webauthn.Credential, error) {
	var encoded string
	err := q.QueryRow(ctx, `
		SELECT hash
		FROM credentials
		WHERE user_id = $1 AND kind = $2`, userID, PasskeyCredentialKind).Scan(&encoded)
	if errors.Is(err, pgx.ErrNoRows) {
		return []webauthn.Credential{}, nil
	}
	if err != nil {
		return nil, err
	}
	var credentials []webauthn.Credential
	if err := json.Unmarshal([]byte(encoded), &credentials); err != nil {
		return nil, fmt.Errorf("decode passkey credentials: %w", err)
	}
	if credentials == nil {
		credentials = []webauthn.Credential{}
	}
	return credentials, nil
}

// AddPasskey appends one serialized credential to the user's passkey row.
// The insert-first path avoids a lost update when the first two enrollments
// race; the conflicting writer then locks and updates the existing row.
func AddPasskey(ctx context.Context, q Q, userID string, credential webauthn.Credential) error {
	encoded, err := json.Marshal([]webauthn.Credential{credential})
	if err != nil {
		return fmt.Errorf("encode passkey credential: %w", err)
	}
	inserted, err := q.Exec(ctx, `
		INSERT INTO credentials (user_id, kind, hash)
		VALUES ($1, $2, $3)
		ON CONFLICT (user_id, kind) DO NOTHING`, userID, PasskeyCredentialKind, string(encoded))
	if err != nil {
		return err
	}
	if inserted.RowsAffected() > 0 {
		return nil
	}

	var existing string
	if err := q.QueryRow(ctx, `
		SELECT hash
		FROM credentials
		WHERE user_id = $1 AND kind = $2
		FOR UPDATE`, userID, PasskeyCredentialKind).Scan(&existing); err != nil {
		return err
	}
	var credentials []webauthn.Credential
	if err := json.Unmarshal([]byte(existing), &credentials); err != nil {
		return fmt.Errorf("decode passkey credentials: %w", err)
	}
	for _, current := range credentials {
		if string(current.ID) == string(credential.ID) {
			return errors.New("passkey credential already exists")
		}
	}
	credentials = append(credentials, credential)
	encoded, err = json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("encode passkey credentials: %w", err)
	}
	_, err = q.Exec(ctx, `
		UPDATE credentials
		SET hash = $3, rotated_at = now()
		WHERE user_id = $1 AND kind = $2`, userID, PasskeyCredentialKind, string(encoded))
	return err
}

// UpdatePasskey replaces a serialized credential after a successful assertion,
// preserving its credential ID while advancing its authenticator state.
func UpdatePasskey(ctx context.Context, q Q, userID string, credential webauthn.Credential) error {
	var existing string
	if err := q.QueryRow(ctx, `
		SELECT hash
		FROM credentials
		WHERE user_id = $1 AND kind = $2
		FOR UPDATE`, userID, PasskeyCredentialKind).Scan(&existing); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return ErrNotFound
		}
		return err
	}
	var credentials []webauthn.Credential
	if err := json.Unmarshal([]byte(existing), &credentials); err != nil {
		return fmt.Errorf("decode passkey credentials: %w", err)
	}
	found := false
	for index := range credentials {
		if string(credentials[index].ID) == string(credential.ID) {
			credentials[index] = credential
			found = true
			break
		}
	}
	if !found {
		return ErrNotFound
	}
	encoded, err := json.Marshal(credentials)
	if err != nil {
		return fmt.Errorf("encode passkey credentials: %w", err)
	}
	_, err = q.Exec(ctx, `
		UPDATE credentials
		SET hash = $3, rotated_at = now()
		WHERE user_id = $1 AND kind = $2`, userID, PasskeyCredentialKind, string(encoded))
	return err
}

// DeletePasskey removes one credential and returns the number of credentials
// removed (zero when the credential or passkey row does not exist).
func DeletePasskey(ctx context.Context, q Q, userID string, credentialID []byte) (int64, error) {
	var existing string
	err := q.QueryRow(ctx, `
		SELECT hash
		FROM credentials
		WHERE user_id = $1 AND kind = $2
		FOR UPDATE`, userID, PasskeyCredentialKind).Scan(&existing)
	if errors.Is(err, pgx.ErrNoRows) {
		return 0, nil
	}
	if err != nil {
		return 0, err
	}
	var credentials []webauthn.Credential
	if err := json.Unmarshal([]byte(existing), &credentials); err != nil {
		return 0, fmt.Errorf("decode passkey credentials: %w", err)
	}
	for index := range credentials {
		if string(credentials[index].ID) != string(credentialID) {
			continue
		}
		credentials = append(credentials[:index], credentials[index+1:]...)
		if len(credentials) == 0 {
			_, err = q.Exec(ctx, `
				DELETE FROM credentials
				WHERE user_id = $1 AND kind = $2`, userID, PasskeyCredentialKind)
		} else {
			encoded, encodeErr := json.Marshal(credentials)
			if encodeErr != nil {
				return 0, fmt.Errorf("encode passkey credentials: %w", encodeErr)
			}
			_, err = q.Exec(ctx, `
				UPDATE credentials
				SET hash = $3, rotated_at = now()
				WHERE user_id = $1 AND kind = $2`, userID, PasskeyCredentialKind, string(encoded))
		}
		if err != nil {
			return 0, err
		}
		return 1, nil
	}
	return 0, nil
}

// GetUserByPasskeyCredID resolves the owning user for a discoverable assertion.
func GetUserByPasskeyCredID(ctx context.Context, q Q, credentialID []byte) (User, error) {
	encodedID := base64.StdEncoding.EncodeToString(credentialID)
	return scanUser(q.QueryRow(ctx, `
		SELECT u.id, u.username, u.email, u.display_name, u.status, u.perm_ver,
		       u.failed_logins, u.locked_until, u.email_verified_at, u.approved_at,
		       u.approved_by, u.created_at, u.updated_at
		FROM users AS u
		JOIN credentials AS c ON c.user_id = u.id AND c.kind = $1
		WHERE EXISTS (
			SELECT 1
			FROM jsonb_array_elements(c.hash::jsonb) AS passkey
			WHERE passkey->>'id' = $2
		)
		LIMIT 1`, PasskeyCredentialKind, encodedID))
}

// CreateWebauthnChallenge stores one short-lived ceremony session.
func CreateWebauthnChallenge(ctx context.Context, q Q, challenge WebauthnChallenge) (WebauthnChallenge, error) {
	if challenge.ID == "" {
		challenge.ID = NewID()
	}
	return scanWebauthnChallenge(q.QueryRow(ctx, `
		INSERT INTO webauthn_challenges
			(id, user_id, kind, challenge, session_data, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, user_id, kind, challenge, session_data, expires_at, created_at`,
		challenge.ID, challenge.UserID, challenge.Kind, challenge.Challenge,
		challenge.SessionData, challenge.ExpiresAt))
}

// ConsumeWebauthnChallenge atomically deletes and returns an unexpired
// ceremony session of the requested kind. Unknown, expired, mismatched-kind,
// and already-consumed challenges are indistinguishable to callers.
func ConsumeWebauthnChallenge(ctx context.Context, q Q, challenge, kind string) (json.RawMessage, error) {
	var sessionData []byte
	err := q.QueryRow(ctx, `
		DELETE FROM webauthn_challenges
		WHERE challenge = $1 AND kind = $2 AND expires_at > now()
		RETURNING session_data`, challenge, kind).Scan(&sessionData)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, ErrNotFound
	}
	if err != nil {
		return nil, err
	}
	return json.RawMessage(sessionData), nil
}

func scanWebauthnChallenge(row pgx.Row) (WebauthnChallenge, error) {
	var challenge WebauthnChallenge
	var userID pgtype.Text
	if err := row.Scan(
		&challenge.ID, &userID, &challenge.Kind, &challenge.Challenge,
		&challenge.SessionData, &challenge.ExpiresAt, &challenge.CreatedAt,
	); err != nil {
		return WebauthnChallenge{}, err
	}
	if userID.Valid {
		value := userID.String
		challenge.UserID = &value
	}
	return challenge, nil
}
