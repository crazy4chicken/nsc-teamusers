package events

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/config"
	"teamusers/internal/store"
)

type auditForwardTestQuery struct {
	published [][]int64
}

func (q *auditForwardTestQuery) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	ids, ok := args[0].([]int64)
	if !ok {
		return pgconn.NewCommandTag(""), errors.New("unexpected outbox ID argument")
	}
	q.published = append(q.published, append([]int64(nil), ids...))
	return pgconn.NewCommandTag("UPDATE 1"), nil
}

func (*auditForwardTestQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (*auditForwardTestQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected query row")
}

func TestAuditForwarderSignsAndAcknowledgesRows(t *testing.T) {
	const secret = "audit forwarding test secret"
	body := []byte(`{"id":17,"action":"user.created"}`)
	type receivedRequest struct {
		method    string
		content   string
		signature string
		body      []byte
	}
	received := make(chan receivedRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestBody, err := io.ReadAll(r.Body)
		received <- receivedRequest{
			method: r.Method, content: r.Header.Get("Content-Type"),
			signature: r.Header.Get("X-Teamusers-Signature-256"), body: requestBody,
		}
		if err != nil {
			t.Errorf("read forwarded body: %v", err)
		}
		w.WriteHeader(http.StatusNoContent)
	}))
	defer server.Close()

	query := &auditForwardTestQuery{}
	forwarder := NewAuditForwarder(query, config.Config{
		AuditForwardEndpoints: []string{server.URL}, AuditForwardSecret: secret,
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	event := store.OutboxEvent{ID: 9, Topic: store.AuditForwardTopic, Payload: body}
	if err := forwarder.dispatchEvents(context.Background(), []store.OutboxEvent{event}); err != nil {
		t.Fatalf("dispatch audit row: %v", err)
	}

	request := <-received
	mac := hmac.New(sha256.New, []byte(secret))
	_, _ = mac.Write(body)
	wantSignature := "sha256=" + hex.EncodeToString(mac.Sum(nil))
	if request.method != http.MethodPost || request.content != "application/json" || request.signature != wantSignature || string(request.body) != string(body) {
		t.Fatalf("forwarded request = %+v, want POST JSON body with signature %q", request, wantSignature)
	}
	if len(query.published) != 1 || len(query.published[0]) != 1 || query.published[0][0] != event.ID {
		t.Fatalf("published outbox IDs = %+v, want [%d]", query.published, event.ID)
	}
}

func TestAuditForwarderAbortsBatchOnFirstFailure(t *testing.T) {
	backoff := notificationRetryBackoff
	notificationRetryBackoff = [3]time.Duration{}
	defer func() { notificationRetryBackoff = backoff }()

	attempts := make(chan string, notificationMaxAttempts*2)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("read forwarded body: %v", err)
		}
		attempts <- string(body)
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	defer server.Close()

	query := &auditForwardTestQuery{}
	forwarder := NewAuditForwarder(query, config.Config{
		AuditForwardEndpoints: []string{server.URL}, AuditForwardSecret: "secret",
	}, slog.New(slog.NewTextHandler(io.Discard, nil)))
	event := store.OutboxEvent{ID: 10, Topic: store.AuditForwardTopic, Payload: []byte(`{"id":18}`)}
	laterEvent := store.OutboxEvent{ID: 11, Topic: store.AuditForwardTopic, Payload: []byte(`{"id":19}`)}
	if err := forwarder.dispatchEvents(context.Background(), []store.OutboxEvent{event, laterEvent}); err == nil {
		t.Fatal("dispatch failed delivery: got nil error")
	}
	if got := len(attempts); got != notificationMaxAttempts {
		t.Fatalf("delivery attempts = %d, want %d before aborting the batch", got, notificationMaxAttempts)
	}
	for range notificationMaxAttempts {
		if body := <-attempts; body != string(event.Payload) {
			t.Fatalf("attempted payload = %q, want only failed row %q", body, event.Payload)
		}
	}
	if len(query.published) != 0 {
		t.Fatalf("failed audit outbox row was acknowledged: %+v", query.published)
	}
}
