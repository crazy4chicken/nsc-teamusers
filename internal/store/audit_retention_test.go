package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type auditRetentionExecCall struct {
	query string
	args  []any
}

type auditRetentionTestQuery struct {
	deletedOutboxRows []int64
	deletedAuditRows  []int64
	outboxCalls       int
	auditCalls        int
	calls             []auditRetentionExecCall
}

func (q *auditRetentionTestQuery) Exec(_ context.Context, query string, args ...any) (pgconn.CommandTag, error) {
	q.calls = append(q.calls, auditRetentionExecCall{query: query, args: append([]any(nil), args...)})
	if strings.Contains(query, "FROM outbox") {
		if len(args) != 3 {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit outbox retention arguments")
		}
		topic, ok := args[0].(string)
		if !ok || topic != AuditForwardTopic {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit outbox retention topic")
		}
		if _, ok := args[1].(time.Time); !ok {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit outbox retention cutoff")
		}
		if _, ok := args[2].(int); !ok {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit outbox retention limit")
		}
		if !strings.Contains(query, "payload->>'at'") || strings.Contains(query, "published_at") {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit outbox retention query")
		}
		if q.outboxCalls >= len(q.deletedOutboxRows) {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit outbox retention batch")
		}
		deleted := q.deletedOutboxRows[q.outboxCalls]
		q.outboxCalls++
		return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", deleted)), nil
	}
	if strings.Contains(query, "FROM audit_log") {
		if len(args) != 2 {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit retention arguments")
		}
		if _, ok := args[0].(time.Time); !ok {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit retention cutoff")
		}
		if _, ok := args[1].(int); !ok {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit retention limit")
		}
		if q.auditCalls >= len(q.deletedAuditRows) {
			return pgconn.NewCommandTag(""), errors.New("unexpected audit retention batch")
		}
		deleted := q.deletedAuditRows[q.auditCalls]
		q.auditCalls++
		return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", deleted)), nil
	}
	return pgconn.NewCommandTag(""), errors.New("unexpected audit retention query")
}

func (*auditRetentionTestQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (*auditRetentionTestQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected query row")
}

func TestDeleteExpiredAuditLogDeletesOutboxCopiesAndAuditRowsInBatches(t *testing.T) {
	cutoff := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	query := &auditRetentionTestQuery{
		deletedOutboxRows: []int64{2},
		deletedAuditRows:  []int64{1000, 1000, 37},
	}
	deleted, err := DeleteExpiredAuditLog(context.Background(), query, cutoff)
	if err != nil {
		t.Fatalf("delete expired audit rows: %v", err)
	}
	if deleted != 2039 {
		t.Fatalf("deleted rows = %d, want 2039 including outbox copies", deleted)
	}
	if query.outboxCalls != 1 || query.auditCalls != 3 || len(query.calls) != 4 {
		t.Fatalf("delete batches = outbox:%d audit:%d total:%d, want 1/3/4", query.outboxCalls, query.auditCalls, len(query.calls))
	}
	for i, call := range query.calls {
		if i == 0 {
			if !strings.Contains(call.query, "FROM outbox") || strings.Contains(call.query, "published_at") {
				t.Fatalf("first retention query = %q, want all expired audit.forward outbox copies", call.query)
			}
			if call.args[0] != AuditForwardTopic || !call.args[1].(time.Time).Equal(cutoff) || call.args[2] != auditRetentionBatchSize {
				t.Fatalf("outbox retention arguments = %v, want topic/cutoff/batch", call.args)
			}
			continue
		}
		if !strings.Contains(call.query, "FROM audit_log") {
			t.Fatalf("retention query %d = %q, want audit_log cleanup", i+1, call.query)
		}
		if !call.args[0].(time.Time).Equal(cutoff) || call.args[1] != auditRetentionBatchSize {
			t.Fatalf("audit retention arguments = %v, want cutoff/batch", call.args)
		}
	}
}
