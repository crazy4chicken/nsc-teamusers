package store

import (
	"context"
	"time"
)

// PasswordHistoryLimit bounds both the policy setting and retained rows.
const PasswordHistoryLimit = 24

// LockPasswordHistory serializes password history writes for one user. Call it
// inside the transaction that records the checked replacement password.
func LockPasswordHistory(ctx context.Context, q Q, userID string) error {
	var lockedID string
	return q.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, userID).Scan(&lockedID)
}

// ListPasswordHistoryHashes returns the most recently set password hashes up
// to limit. The result is ordered newest first.
func ListPasswordHistoryHashes(ctx context.Context, q Q, userID string, limit int) ([]string, error) {
	if limit <= 0 {
		return nil, nil
	}
	if limit > PasswordHistoryLimit {
		limit = PasswordHistoryLimit
	}
	rows, err := q.Query(ctx, `
		SELECT hash
		FROM password_history
		WHERE user_id = $1
		ORDER BY set_at DESC, history_id DESC
		LIMIT $2`, userID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	hashes := make([]string, 0, limit)
	for rows.Next() {
		var hash string
		if err := rows.Scan(&hash); err != nil {
			return nil, err
		}
		hashes = append(hashes, hash)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return hashes, nil
}

// MaxConfiguredPasswordHistoryCount returns the largest history count among
// the user's currently effective policies, capped at PasswordHistoryLimit.
func MaxConfiguredPasswordHistoryCount(ctx context.Context, q Q, userID string, now time.Time) (int, error) {
	policies, err := ListEffectivePasswordPolicies(ctx, q, userID, now)
	if err != nil {
		return 0, err
	}
	maxCount := 0
	for _, policy := range policies {
		if policy.HistoryCount != nil && *policy.HistoryCount > maxCount {
			maxCount = *policy.HistoryCount
		}
	}
	if maxCount > PasswordHistoryLimit {
		maxCount = PasswordHistoryLimit
	}
	return maxCount, nil
}

// RecordPasswordHistory inserts a password hash if it is not already present,
// then prunes the user's history to the maximum count among effective policies.
func RecordPasswordHistory(ctx context.Context, q Q, userID, hash string, setAt, now time.Time) error {
	retention, err := MaxConfiguredPasswordHistoryCount(ctx, q, userID, now)
	if err != nil {
		return err
	}
	return RecordPasswordHistoryForCount(ctx, q, userID, hash, setAt, retention)
}

// RecordPasswordHistoryForCount inserts a password hash if it is not already
// present, then prunes the user's history to the specified effective count.
func RecordPasswordHistoryForCount(ctx context.Context, q Q, userID, hash string, setAt time.Time, retention int) error {
	if retention < 0 {
		retention = 0
	}
	if retention > PasswordHistoryLimit {
		retention = PasswordHistoryLimit
	}
	if _, err := q.Exec(ctx, `
		INSERT INTO password_history (user_id, hash, set_at)
		SELECT $1, $2, $3
		WHERE NOT EXISTS (
			SELECT 1 FROM password_history WHERE user_id = $1 AND hash = $2
		)`, userID, hash, setAt); err != nil {
		return err
	}
	_, err := q.Exec(ctx, `
		DELETE FROM password_history
		WHERE user_id = $1
		  AND history_id IN (
			SELECT history_id
			FROM password_history
			WHERE user_id = $1
			ORDER BY set_at DESC, history_id DESC
			OFFSET $2
		  )`, userID, retention)
	return err
}
