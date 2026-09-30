package store

import (
	"context"
	"time"
)

const auditRetentionBatchSize = 1000

// DeleteExpiredAuditLog removes expired audit rows and their audit-forwarding
// outbox copies in bounded batches and returns the total number of rows deleted.
func DeleteExpiredAuditLog(ctx context.Context, q Q, cutoff time.Time) (int64, error) {
	outboxDeleted, err := deleteExpiredAuditOutbox(ctx, q, cutoff)
	if err != nil {
		return outboxDeleted, err
	}
	auditDeleted, err := deleteExpiredAuditRows(ctx, q, cutoff)
	return outboxDeleted + auditDeleted, err
}

func deleteExpiredAuditOutbox(ctx context.Context, q Q, cutoff time.Time) (int64, error) {
	var total int64
	for {
		result, err := q.Exec(ctx, `
			WITH expired AS (
				SELECT id FROM outbox
				WHERE topic = $1 AND CASE WHEN topic = $1 THEN (payload->>'at')::timestamptz END < $2
				ORDER BY id LIMIT $3
			)
			DELETE FROM outbox AS forward
			USING expired
			WHERE forward.id = expired.id`, AuditForwardTopic, cutoff, auditRetentionBatchSize)
		if err != nil {
			return total, err
		}
		deleted := result.RowsAffected()
		total += deleted
		if deleted < auditRetentionBatchSize {
			return total, nil
		}
	}
}

func deleteExpiredAuditRows(ctx context.Context, q Q, cutoff time.Time) (int64, error) {
	var total int64
	for {
		result, err := q.Exec(ctx, `
			WITH expired AS (
				SELECT id FROM audit_log WHERE at < $1 ORDER BY id LIMIT $2
			)
			DELETE FROM audit_log AS audit
			USING expired
			WHERE audit.id = expired.id`, cutoff, auditRetentionBatchSize)
		if err != nil {
			return total, err
		}
		deleted := result.RowsAffected()
		total += deleted
		if deleted < auditRetentionBatchSize {
			return total, nil
		}
	}
}
