package store

import (
	"context"
	"errors"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

// IdempotencyTTL is the retention period for completed idempotency claims.
const IdempotencyTTL = 24 * time.Hour

// IdempotencyRecord is a claimed request and, when complete, its response.
type IdempotencyRecord struct {
	Scope       string
	Key         string
	Fingerprint string
	Status      *int
	Response    []byte
	CreatedAt   time.Time
	ExpiresAt   time.Time
}

// ClaimIdempotency claims a new key or returns the existing claim. The bool is
// true only when this call inserted the claim.
func ClaimIdempotency(ctx context.Context, q Q, scope, key, fingerprint string, createdAt, expiresAt time.Time) (IdempotencyRecord, bool, error) {
	if _, err := DeleteExpiredIdempotency(ctx, q, createdAt); err != nil {
		return IdempotencyRecord{}, false, err
	}

	var record IdempotencyRecord
	var status pgtype.Int4
	if err := q.QueryRow(ctx, `
		INSERT INTO idempotency_keys (scope, key, fingerprint, status, response, created_at, expires_at)
		VALUES ($1, $2, $3, NULL, NULL, $4, $5)
		ON CONFLICT (scope, key) DO NOTHING
		RETURNING scope, key, fingerprint, status, response, created_at, expires_at`,
		scope, key, fingerprint, createdAt, expiresAt,
	).Scan(&record.Scope, &record.Key, &record.Fingerprint, &status, &record.Response, &record.CreatedAt, &record.ExpiresAt); err == nil {
		if status.Valid {
			value := int(status.Int32)
			record.Status = &value
		}
		return record, true, nil
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return IdempotencyRecord{}, false, err
	}

	status = pgtype.Int4{}
	err := q.QueryRow(ctx, `
		SELECT scope, key, fingerprint, status, response, created_at, expires_at
		FROM idempotency_keys
		WHERE scope = $1 AND key = $2`, scope, key).
		Scan(&record.Scope, &record.Key, &record.Fingerprint, &status, &record.Response, &record.CreatedAt, &record.ExpiresAt)
	if err != nil {
		return IdempotencyRecord{}, false, err
	}
	if status.Valid {
		value := int(status.Int32)
		record.Status = &value
	}
	return record, false, nil
}

// CompleteIdempotency stores the response for an existing claim.
func CompleteIdempotency(ctx context.Context, q Q, scope, key string, status int, response []byte) error {
	_, err := q.Exec(ctx, `
		UPDATE idempotency_keys
		SET status = $3, response = $4
		WHERE scope = $1 AND key = $2`, scope, key, status, response)
	return err
}

// DeleteIdempotency releases a claim that must not be replayed, such as a
// transient server or rate-limit response.
func DeleteIdempotency(ctx context.Context, q Q, scope, key string) error {
	_, err := q.Exec(ctx, `DELETE FROM idempotency_keys WHERE scope = $1 AND key = $2`, scope, key)
	return err
}

// DeleteExpiredIdempotency removes claims whose retention period has elapsed.
func DeleteExpiredIdempotency(ctx context.Context, q Q, now time.Time) (int64, error) {
	result, err := q.Exec(ctx, `DELETE FROM idempotency_keys WHERE expires_at <= $1`, now)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}
