package test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestIdempotencyKeySemantics(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	body := []byte(`{"slug":"idempotency-team","name":"Idempotency Team"}`)

	status, firstBody, replayed := idempotencyRequest(t, stack, http.MethodPost, "/teams", body, adminToken, "team-create")
	if status != http.StatusCreated {
		t.Fatalf("first idempotent create status = %d, want %d: %s", status, http.StatusCreated, firstBody)
	}
	if replayed != "" {
		t.Fatalf("first idempotent create replay header = %q, want empty", replayed)
	}

	status, secondBody, replayed := idempotencyRequest(t, stack, http.MethodPost, "/teams", body, adminToken, "team-create")
	if status != http.StatusCreated {
		t.Fatalf("replayed create status = %d, want %d: %s", status, http.StatusCreated, secondBody)
	}
	if !bytes.Equal(firstBody, secondBody) {
		t.Fatalf("replayed body differs:\nfirst: %s\nsecond: %s", firstBody, secondBody)
	}
	if replayed != "true" {
		t.Fatalf("replayed header = %q, want true", replayed)
	}

	var teamCount int
	if err := stack.database.pool.QueryRow(context.Background(), `SELECT count(*) FROM teams WHERE slug = $1`, "idempotency-team").Scan(&teamCount); err != nil {
		t.Fatalf("count idempotent teams: %v", err)
	}
	if teamCount != 1 {
		t.Fatalf("idempotent team count = %d, want 1", teamCount)
	}

	differentBody := []byte(`{"slug":"idempotency-team-different","name":"Different"}`)
	status, conflictBody, replayed := idempotencyRequest(t, stack, http.MethodPost, "/teams", differentBody, adminToken, "team-create")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("different-body status = %d, want %d: %s", status, http.StatusUnprocessableEntity, conflictBody)
	}
	if !bytes.Contains(conflictBody, []byte(`"idempotency_conflict"`)) {
		t.Fatalf("different-body response = %s, want idempotency_conflict", conflictBody)
	}
	if replayed != "" {
		t.Fatalf("different-body replay header = %q, want empty", replayed)
	}

	var created teamResponse
	decodeResponse(t, firstBody, &created)
	status, getBody, replayed := idempotencyRequest(t, stack, http.MethodGet, "/teams/"+created.ID, nil, adminToken, "team-create")
	if status != http.StatusOK {
		t.Fatalf("GET with idempotency key status = %d, want %d: %s", status, http.StatusOK, getBody)
	}
	if replayed != "" {
		t.Fatalf("GET replay header = %q, want empty", replayed)
	}

	noKeyBody := map[string]string{"slug": "no-idempotency-team", "name": "No Idempotency"}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/teams", noKeyBody, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("no-key first create status = %d, want %d", status, http.StatusCreated)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/teams", noKeyBody, adminToken)
	if status != http.StatusConflict {
		t.Fatalf("no-key duplicate create status = %d, want %d", status, http.StatusConflict)
	}
}

func TestIdempotencyInProgress(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	body := []byte(`{"slug":"idempotency-in-progress","name":"In Progress"}`)
	key := "in-progress"
	authorization := "Bearer " + adminToken
	scopeDigest := sha256.Sum256([]byte(authorization))
	fingerprintDigest := sha256.Sum256(body)
	now := time.Now().UTC()
	_, err := stack.database.pool.Exec(context.Background(), `
		INSERT INTO idempotency_keys (scope, key, fingerprint, status, response, created_at, expires_at)
		VALUES ($1, $2, $3, NULL, NULL, $4, $5)`,
		hex.EncodeToString(scopeDigest[:]), key, hex.EncodeToString(fingerprintDigest[:]), now, now.Add(time.Hour))
	if err != nil {
		t.Fatalf("insert in-progress idempotency claim: %v", err)
	}

	status, responseBody, replayed := idempotencyRequest(t, stack, http.MethodPost, "/teams", body, adminToken, key)
	if status != http.StatusConflict {
		t.Fatalf("in-progress status = %d, want %d: %s", status, http.StatusConflict, responseBody)
	}
	if !bytes.Contains(responseBody, []byte(`"idempotency_in_progress"`)) {
		t.Fatalf("in-progress response = %s, want idempotency_in_progress", responseBody)
	}
	if replayed != "" {
		t.Fatalf("in-progress replay header = %q, want empty", replayed)
	}
}

func idempotencyRequest(t *testing.T, stack *integrationStack, method, path string, body []byte, bearer, key string) (int, []byte, string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, stack.baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, path, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	if key != "" {
		request.Header.Set("Idempotency-Key", key)
	}
	response, err := stack.client.Do(request)
	if err != nil {
		t.Fatalf("perform %s %s request: %v", method, path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	return response.StatusCode, responseBody, response.Header.Get("Idempotency-Replayed")
}
