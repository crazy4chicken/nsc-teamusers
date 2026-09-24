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

// Writer appends audit records. It has no mutable state and may be shared by
// all HTTP handlers.
type Writer struct{}

// NewWriter constructs an audit writer.
func NewWriter() *Writer {
	return &Writer{}
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
	return store.AppendAuditLog(ctx, q, store.AuditEntry{
		TeamID:    entry.TeamID,
		ActorID:   entry.ActorID,
		Action:    entry.Action,
		Target:    entry.Target,
		Diff:      diff,
		RequestID: requestID,
	})
}
