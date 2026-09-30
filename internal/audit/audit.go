// Package audit provides the transactional append-only audit writer.
package audit

import (
	"context"
	"encoding/json"

	"github.com/go-chi/chi/v5/middleware"

	"teamusers/internal/store"
)

// Entry describes one mutation for the append-only audit log.
type Entry struct {
	TeamID  *string
	ActorID *string
	Action  string
	Target  string
	Before  any
	After   any
}

// AuditEntry is retained as a descriptive alias for callers that prefer the
// storage-facing name.
type AuditEntry = Entry

// Writer appends audit records. It carries only the optional forwarding
// setting and may be shared by all HTTP handlers.
type Writer struct {
	forwardingEnabled bool
}

// NewWriter constructs an audit writer without forwarding.
func NewWriter() *Writer {
	return &Writer{}
}

// NewForwardingWriter constructs an audit writer that also queues rows for
// asynchronous external delivery.
func NewForwardingWriter() *Writer {
	return &Writer{forwardingEnabled: true}
}

// Append writes one audit row using q. Callers should pass the transaction
// query handle when recording a mutation so the row commits atomically with
// that mutation.
func (w *Writer) Append(ctx context.Context, q store.Q, entry Entry) (store.AuditEntry, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	diff, err := json.Marshal(struct {
		Before any `json:"before"`
		After  any `json:"after"`
	}{Before: entry.Before, After: entry.After})
	if err != nil {
		return store.AuditEntry{}, err
	}
	var requestID *string
	if value := middleware.GetReqID(ctx); value != "" {
		requestID = &value
	}
	auditEntry := store.AuditEntry{
		TeamID:    entry.TeamID,
		ActorID:   entry.ActorID,
		Action:    entry.Action,
		Target:    entry.Target,
		Diff:      diff,
		RequestID: requestID,
	}
	if w.forwardingEnabled {
		return store.AppendAuditLogWithForward(ctx, q, auditEntry)
	}
	return store.AppendAuditLog(ctx, q, auditEntry)
}
