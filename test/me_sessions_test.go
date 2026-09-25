package test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type meProfileTestResponse struct {
	ID              string  `json:"id"`
	Username        string  `json:"username"`
	Email           *string `json:"email"`
	DisplayName     string  `json:"display_name"`
	Status          string  `json:"status"`
	EmailVerifiedAt *string `json:"email_verified_at"`
	CreatedAt       string  `json:"created_at"`
}

type meSessionTestResponse struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
	ExpiresAt string `json:"expires_at"`
}

func loginMeTestPair(t *testing.T, stack *integrationStack, username, password string) tokenPair {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login %q status = %d, want %d: %s", username, status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	return pair
}

func listMeTestSessions(t *testing.T, stack *integrationStack, path, bearer string) []meSessionTestResponse {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodGet, path, nil, bearer)
	if status != http.StatusOK {
		t.Fatalf("list sessions %s status = %d, want %d: %s", path, status, http.StatusOK, body)
	}
	var sessions []meSessionTestResponse
	decodeResponse(t, body, &sessions)
	return sessions
}

func TestMeProfilePasswordAndSessions(t *testing.T) {
	stack := newIntegrationStack(t)
	alice := seedPasswordUser(t, context.Background(), stack.database.pool, "me-alice", "OldPassword1")
	bob := seedPasswordUser(t, context.Background(), stack.database.pool, "me-bob", "BobPassword1")
	admin := seedPasswordUser(t, context.Background(), stack.database.pool, "me-admin", "AdminPassword1")
	bootstrapTestAdmin(t, context.Background(), stack.database.pool, admin.ID)

	if status, _ := stack.jsonRequest(t, http.MethodGet, "/me", nil, ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated /me status = %d, want %d", status, http.StatusUnauthorized)
	}

	alicePair := loginMeTestPair(t, stack, alice.Username, "OldPassword1")
	status, body := stack.jsonRequest(t, http.MethodGet, "/me", nil, alicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var profile meProfileTestResponse
	decodeResponse(t, body, &profile)
	if profile.ID != alice.ID || profile.Username != alice.Username || profile.Status != "active" {
		t.Fatalf("unexpected own profile: %+v", profile)
	}
	var profileFields map[string]json.RawMessage
	decodeResponse(t, body, &profileFields)
	if _, found := profileFields["password"]; found {
		t.Fatal("GET /me returned password data")
	}
	if _, found := profileFields["credential"]; found {
		t.Fatal("GET /me returned credential data")
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/me", map[string]string{
		"display_name": "Alice Updated",
	}, alicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("PATCH /me status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &profile)
	if profile.DisplayName != "Alice Updated" {
		t.Fatalf("display name = %q, want Alice Updated", profile.DisplayName)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/me", map[string]string{
		"email": "new@example.test",
	}, alicePair.AccessToken)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "email") {
		t.Fatalf("PATCH /me email status = %d body=%s, want email unsupported 422", status, body)
	}

	alicePair2 := loginMeTestPair(t, stack, alice.Username, "OldPassword1")
	sessions := listMeTestSessions(t, stack, "/me/sessions", alicePair.AccessToken)
	if len(sessions) != 2 {
		t.Fatalf("own session count = %d, want 2", len(sessions))
	}
	deletedSessionID := sessions[0].ID
	status, body = stack.jsonRequest(t, http.MethodDelete, "/me/sessions/"+deletedSessionID, nil, alicePair.AccessToken)
	if status != http.StatusNoContent {
		t.Fatalf("DELETE own session status = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": alicePair.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("deleted own refresh status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": alicePair2.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("other own refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var aliceRotatedPair tokenPair
	decodeResponse(t, body, &aliceRotatedPair)
	assertTokenPair(t, aliceRotatedPair)

	bobPair := loginMeTestPair(t, stack, bob.Username, "BobPassword1")
	bobSessions := listMeTestSessions(t, stack, "/me/sessions", bobPair.AccessToken)
	if len(bobSessions) != 1 {
		t.Fatalf("bob session count = %d, want 1", len(bobSessions))
	}
	status, _ = stack.jsonRequest(t, http.MethodDelete, "/me/sessions/"+bobSessions[0].ID, nil, alicePair.AccessToken)
	if status != http.StatusNotFound {
		t.Fatalf("cross-user self session delete status = %d, want %d", status, http.StatusNotFound)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": bobPair.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("cross-user delete changed bob refresh status = %d, want %d", status, http.StatusOK)
	}
	var bobRotatedPair tokenPair
	decodeResponse(t, body, &bobRotatedPair)
	assertTokenPair(t, bobRotatedPair)

	status, _ = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "wrong-password1",
		"new_password":     "NewPassword2",
	}, alicePair.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong current password status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "OldPassword1",
		"new_password":     "weak1",
	}, alicePair.AccessToken)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("weak new password status = %d body=%s, want weak_password 422", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "OldPassword1",
		"new_password":     "NewPassword2",
	}, alicePair.AccessToken)
	if status != http.StatusOK || !strings.Contains(string(body), "sign in again") {
		t.Fatalf("password change status = %d body=%s, want re-login message", status, body)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": aliceRotatedPair.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("refresh after password change status = %d, want %d", status, http.StatusUnauthorized)
	}
	newAlicePair := loginMeTestPair(t, stack, alice.Username, "NewPassword2")
	if newAlicePair.AccessToken == "" {
		t.Fatal("login with new password returned empty access token")
	}

	adminPair := loginMeTestPair(t, stack, admin.Username, "AdminPassword1")
	bobPair2 := loginMeTestPair(t, stack, bob.Username, "BobPassword1")
	adminSessions := listMeTestSessions(t, stack, "/users/"+bob.ID+"/sessions", adminPair.AccessToken)
	if len(adminSessions) != 2 {
		t.Fatalf("admin session count = %d, want 2", len(adminSessions))
	}
	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+bob.ID+"/sessions/"+adminSessions[0].ID, nil, adminPair.AccessToken)
	if status != http.StatusNoContent {
		t.Fatalf("admin delete session status = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": bobRotatedPair.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("admin-deleted refresh status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, _ = stack.jsonRequest(t, http.MethodDelete, "/users/"+bob.ID+"/sessions", nil, adminPair.AccessToken)
	if status != http.StatusNoContent {
		t.Fatalf("admin revoke-all status = %d, want %d", status, http.StatusNoContent)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": bobPair2.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("admin revoke-all refresh status = %d, want %d", status, http.StatusUnauthorized)
	}

	service := seedPasswordUser(t, context.Background(), stack.database.pool, "me-service", "ServicePassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+service.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminPair.AccessToken)
	if status != http.StatusCreated {
		t.Fatalf("service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("service login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	status, _ = stack.jsonRequest(t, http.MethodGet, "/me", nil, servicePair.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("service /me status = %d, want %d", status, http.StatusUnauthorized)
	}
}
