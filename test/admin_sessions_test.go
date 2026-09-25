package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"net/http"
	"testing"
)

func TestAdminSessionEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	target := seedPasswordUser(t, context.Background(), stack.database.pool, "session-target", "SessionTargetPassword1")
	first := loginSessionTestUser(t, stack, target.Username, "SessionTargetPassword1")
	second := loginSessionTestUser(t, stack, target.Username, "SessionTargetPassword1")

	status, body := stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/sessions", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list target sessions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var sessions []struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &sessions)
	if len(sessions) != 2 {
		t.Fatalf("target sessions = %d, want 2: %s", len(sessions), body)
	}
	seen := make(map[string]bool, len(sessions))
	for _, session := range sessions {
		seen[session.ID] = true
	}
	firstID := refreshSessionID(first.RefreshToken)
	secondID := refreshSessionID(second.RefreshToken)
	if !seen[firstID] || !seen[secondID] {
		t.Fatalf("target sessions = %+v, want active session IDs %q and %q", sessions, firstID, secondID)
	}

	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+target.ID+"/sessions/does-not-exist", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown target session status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/does-not-exist/sessions", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown user revoke-all status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/does-not-exist/sessions", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown user list sessions status = %d, want %d: %s", status, http.StatusNotFound, body)
	}

	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+target.ID+"/sessions/"+firstID, nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("revoke one target session = %d %q, want empty %d", status, body, http.StatusNoContent)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": first.RefreshToken}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("revoked target refresh status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": second.RefreshToken}, "")
	if status != http.StatusOK {
		t.Fatalf("other target refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var replacement tokenPair
	decodeResponse(t, body, &replacement)
	assertTokenPair(t, replacement)

	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/sessions", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list target sessions after one revoke status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &sessions)
	if len(sessions) != 1 || sessions[0].ID != refreshSessionID(replacement.RefreshToken) {
		t.Fatalf("target sessions after one revoke = %+v, want replacement session only", sessions)
	}

	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+target.ID+"/sessions", nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("revoke all target sessions = %d %q, want empty %d", status, body, http.StatusNoContent)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": replacement.RefreshToken}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("refresh after revoke-all status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/sessions", nil, second.AccessToken)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin list sessions status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}

func loginSessionTestUser(t *testing.T, stack *integrationStack, username, password string) tokenPair {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("session test login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	return pair
}

func refreshSessionID(refreshToken string) string {
	digest := sha256.Sum256([]byte(refreshToken))
	return hex.EncodeToString(digest[:])
}
