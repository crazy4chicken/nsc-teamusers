package store

import (
	"context"
	"encoding/json"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
)

// DeleteExpiredStepUpChallenges removes challenges that have passed their application-clock expiry.
func DeleteExpiredStepUpChallenges(ctx context.Context, q Q, now time.Time) error {
	_, err := q.Exec(ctx, `DELETE FROM step_up_challenges WHERE expires_at <= $1`, now)
	return err
}

// CreateStepUpChallenge persists a user- and refresh-session-bound challenge.
func CreateStepUpChallenge(ctx context.Context, q Q, challenge StepUpChallenge) error {
	if challenge.ID == "" {
		return errors.New("step-up challenge ID is required")
	}
	_, err := q.Exec(ctx, `
		INSERT INTO step_up_challenges
			(id, user_id, session_id, purpose, methods, webauthn_session, expires_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		challenge.ID, challenge.UserID, challenge.SessionID, challenge.Purpose, challenge.Methods,
		challenge.WebauthnSession, challenge.ExpiresAt)
	return err
}

// GetStepUpChallengeForUpdate locks a persisted challenge until its proof and
// refresh-session rotation either commit together or roll back together.
func GetStepUpChallengeForUpdate(ctx context.Context, q Q, id string) (StepUpChallenge, error) {
	return scanStepUpChallenge(q.QueryRow(ctx, `
		SELECT id, user_id, session_id, purpose, methods, webauthn_session, expires_at, created_at
		FROM step_up_challenges WHERE id = $1 FOR UPDATE`, id))
}

// ConsumeStepUpChallenge deletes one unexpired challenge bound to the expected
// user, refresh session, and purpose.
func ConsumeStepUpChallenge(ctx context.Context, q Q, id, userID, sessionID, purpose string, now time.Time) error {
	var consumedID string
	err := q.QueryRow(ctx, `
		DELETE FROM step_up_challenges
		WHERE id = $1 AND user_id = $2 AND session_id = $3 AND purpose = $4 AND expires_at > $5
		RETURNING id`, id, userID, sessionID, purpose, now).Scan(&consumedID)
	if errors.Is(err, pgx.ErrNoRows) {
		return ErrNotFound
	}
	return err
}

func scanStepUpChallenge(row pgx.Row) (StepUpChallenge, error) {
	var challenge StepUpChallenge
	var webauthnSession []byte
	if err := row.Scan(
		&challenge.ID, &challenge.UserID, &challenge.SessionID, &challenge.Purpose,
		&challenge.Methods, &webauthnSession, &challenge.ExpiresAt, &challenge.CreatedAt,
	); err != nil {
		return StepUpChallenge{}, err
	}
	if webauthnSession != nil {
		challenge.WebauthnSession = json.RawMessage(webauthnSession)
	}
	return challenge, nil
}
