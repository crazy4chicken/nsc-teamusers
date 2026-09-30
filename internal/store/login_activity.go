package store

import (
	"context"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const (
	loginActivityRetentionBatchSize = 1000
	loginActivityUsernameMaxBytes   = 256
	loginActivityUserAgentMaxBytes  = 512
)

func sanitizeLoginActivity(activity LoginActivity) LoginActivity {
	activity.AttemptedUsername = sanitizeLoginActivityValue(activity.AttemptedUsername, loginActivityUsernameMaxBytes)
	activity.UserAgent = sanitizeLoginActivityValue(activity.UserAgent, loginActivityUserAgentMaxBytes)
	return activity
}

func sanitizeLoginActivityValue(value string, maxBytes int) string {
	if value == "" || maxBytes <= 0 {
		return ""
	}
	capacity := len(value)
	if capacity > maxBytes {
		capacity = maxBytes
	}
	var sanitized strings.Builder
	sanitized.Grow(capacity)
	for _, character := range value {
		if unicode.IsControl(character) {
			continue
		}
		if sanitized.Len()+utf8.RuneLen(character) > maxBytes {
			break
		}
		sanitized.WriteRune(character)
	}
	return sanitized.String()
}

func CreateLoginActivity(ctx context.Context, q Q, activity LoginActivity) error {
	activity = sanitizeLoginActivity(activity)
	if activity.At.IsZero() {
		activity.At = time.Now().UTC()
	}
	_, err := q.Exec(ctx, `
		INSERT INTO login_activity (user_id, attempted_username, at, ip, user_agent, method, result)
		VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		activity.UserID, activity.AttemptedUsername, activity.At, activity.IP,
		activity.UserAgent, activity.Method, activity.Result)
	return err
}

// DeleteExpiredLoginActivity removes stale rows in bounded batches.
func DeleteExpiredLoginActivity(ctx context.Context, q Q, cutoff time.Time) (int64, error) {
	var total int64
	for {
		result, err := q.Exec(ctx, `
			WITH expired AS (
				SELECT id
				FROM login_activity
				WHERE at < $1
				ORDER BY id
				LIMIT $2
			)
			DELETE FROM login_activity AS activity
			USING expired
			WHERE activity.id = expired.id`, cutoff, loginActivityRetentionBatchSize)
		if err != nil {
			return total, err
		}
		deleted := result.RowsAffected()
		total += deleted
		if deleted < loginActivityRetentionBatchSize {
			return total, nil
		}
	}
}

// ListLoginActivity returns one user's activity in descending insertion order.
func ListLoginActivity(ctx context.Context, q Q, userID string, cursor int64, limit int) ([]LoginActivity, int64, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor <= 0 {
		rows, err = q.Query(ctx, `
			SELECT id, user_id, attempted_username, at, ip, user_agent, method, result
			FROM login_activity
			WHERE user_id = $1
			ORDER BY id DESC
			LIMIT $2`, userID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, user_id, attempted_username, at, ip, user_agent, method, result
			FROM login_activity
			WHERE user_id = $1 AND id < $2
			ORDER BY id DESC
			LIMIT $3`, userID, cursor, limit)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()

	entries := make([]LoginActivity, 0, limit)
	for rows.Next() {
		entry, err := scanLoginActivity(rows)
		if err != nil {
			return nil, 0, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(entries) == limit {
		return entries, entries[len(entries)-1].ID, nil
	}
	return entries, 0, nil
}

func scanLoginActivity(row pgx.Row) (LoginActivity, error) {
	var entry LoginActivity
	var userID pgtype.Text
	if err := row.Scan(
		&entry.ID, &userID, &entry.AttemptedUsername, &entry.At,
		&entry.IP, &entry.UserAgent, &entry.Method, &entry.Result,
	); err != nil {
		return LoginActivity{}, err
	}
	entry.UserID = textPointer(userID)
	return entry, nil
}
