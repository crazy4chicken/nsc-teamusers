package test

import (
	"context"
	"net/http"
	"testing"
	"time"
)

func TestAdminKeyRotationIsIdempotentAndAudited(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, _ := stack.jsonRequest(t, http.MethodPost, "/keys/rotate", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("key rotation without token status = %d, want %d", status, http.StatusUnauthorized)
	}

	headers := map[string]string{"Idempotency-Key": "key-rotation-replay"}
	status, body := stack.jsonRequestHeaders(t, http.MethodPost, "/keys/rotate", nil, adminToken, headers)
	if status != http.StatusOK {
		t.Fatalf("key rotation status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var first struct {
		Kid      string    `json:"kid"`
		RetireAt time.Time `json:"retire_at"`
	}
	decodeResponse(t, body, &first)
	if first.Kid == "" || first.RetireAt.IsZero() {
		t.Fatalf("key rotation response = %+v", first)
	}

	status, replay := stack.jsonRequestHeaders(t, http.MethodPost, "/keys/rotate", nil, adminToken, headers)
	if status != http.StatusOK || string(replay) != string(body) {
		t.Fatalf("key rotation replay = %d %s, want original response %s", status, replay, body)
	}

	var outboxCount int64
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT COUNT(*) FROM outbox WHERE topic = 'key.rotated'`).Scan(&outboxCount); err != nil {
		t.Fatalf("count key rotation outbox rows: %v", err)
	}
	if outboxCount != 1 {
		t.Fatalf("key rotation outbox rows = %d, want one", outboxCount)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/audit", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list audit after key rotation = %d, want %d: %s", status, http.StatusOK, body)
	}
	var auditLog auditResponse
	decodeResponse(t, body, &auditLog)
	for _, entry := range auditLog.Items {
		if entry.Action == "key.rotated" {
			return
		}
	}
	t.Fatalf("audit entries = %+v, want key.rotated", auditLog.Items)
}
