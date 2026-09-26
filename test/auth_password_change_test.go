package test

import (
	"context"
	"net/http"
	"strings"
	"testing"

	"teamusers/internal/store"
)

func TestProvisionedPasswordRequiresFirstLoginChange(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "first-login-user",
		"email":    "first-login-user@example.test",
		"password": "ProvisionedPassword1",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("provisioned user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var created userResponse
	decodeResponse(t, body, &created)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": created.Username,
		"password": "ProvisionedPassword1",
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "password_change_required") {
		t.Fatalf("first login = %d %s, want password_change_required 403", status, body)
	}
	var challenge struct {
		ChangeToken string `json:"change_token"`
	}
	decodeResponse(t, body, &challenge)
	if challenge.ChangeToken == "" {
		t.Fatal("first-login response has no change_token")
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, challenge.ChangeToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("change token at GET /me = %d %s, want 401", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": challenge.ChangeToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("change token at /auth/refresh = %d %s, want 401", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "wrong-password1",
		"new_password":     "ReplacementPassword2",
	}, challenge.ChangeToken)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_credentials") {
		t.Fatalf("wrong forced-change password = %d %s, want invalid_credentials 401", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "ProvisionedPassword1",
		"new_password":     "ReplacementPassword2",
	}, challenge.ChangeToken)
	if status != http.StatusOK {
		t.Fatalf("forced password change = %d %s, want 200", status, body)
	}
	credential, err := store.GetCredential(context.Background(), stack.database.pool, created.ID, "password")
	if err != nil {
		t.Fatalf("load changed credential: %v", err)
	}
	if credential.MustChange {
		t.Fatal("changed password credential still requires a change")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": created.Username,
		"password": "ReplacementPassword2",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login after forced change = %d %s, want 200", status, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("profile after forced change = %d %s, want 200", status, body)
	}
}
