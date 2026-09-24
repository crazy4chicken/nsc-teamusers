package store

import (
	"context"
	"time"
)

// DeleteExpiredSessions removes refresh-token rows whose ordinary token TTL
// has elapsed and returns the number of deleted rows.
func DeleteExpiredSessions(ctx context.Context, q Q, now time.Time) (int64, error) {
	result, err := q.Exec(ctx, `DELETE FROM sessions WHERE expires_at < $1`, now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
