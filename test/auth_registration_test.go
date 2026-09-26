package test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

type registrationResponse struct {
	ID     string `json:"id"`
	Status string `json:"status"`
}

func TestRegistrationClosed(t *testing.T) {
	stack := newIntegrationStack(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "closed-user",
		"email":    "closed-user@example.test",
		"password": "correct-password1",
	}, "")
	if status != http.StatusForbidden {
		t.Fatalf("closed registration status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
	if !strings.Contains(string(body), "registration_closed") {
		t.Fatalf("closed registration problem = %s, want registration_closed", body)
	}
}

func TestRegistrationVerificationRateLimit(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "open")
	for attempt := range 30 {
		status, body := stack.jsonRequest(t, http.MethodPost, "/auth/verify-email", nil, "")
		if status != http.StatusBadRequest {
			t.Fatalf("verification attempt %d status = %d, want %d: %s", attempt+1, status, http.StatusBadRequest, body)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/verify-email", nil, "")
	if status != http.StatusTooManyRequests {
		t.Fatalf("verification burst status = %d, want %d: %s", status, http.StatusTooManyRequests, body)
	}
}

func TestRegistrationDuplicateGenericFailure(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "open")
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "duplicate-user",
		"email":    "first@example.test",
		"password": "correct-password1",
	}, "")
	if status != http.StatusCreated {
		t.Fatalf("initial registration status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "duplicate-user",
		"email":    "second@example.test",
		"password": "correct-password1",
	}, "")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("duplicate registration status = %d, want %d: %s", status, http.StatusUnprocessableEntity, body)
	}
	if !strings.Contains(string(body), "registration failed") {
		t.Fatalf("duplicate registration problem = %s, want generic registration failed title", body)
	}
	if strings.Contains(string(body), "duplicate-user") || strings.Contains(string(body), "second@example.test") || strings.Contains(string(body), "first@example.test") {
		t.Fatalf("duplicate registration leaked identity details: %s", body)
	}
}

func TestUsernameStoredLowercase(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "open")
	const (
		mixedUsername = "MiXeDUser"
		password      = "MixedUserPassword1"
	)
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": mixedUsername,
		"email":    "mixed-user@example.test",
		"password": password,
	}, "")
	if status != http.StatusCreated {
		t.Fatalf("mixed-case registration status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var registered registrationResponse
	decodeResponse(t, body, &registered)

	token := registrationToken(t, stack, registered.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/verify-email", map[string]string{"token": token}, "")
	if status != http.StatusNoContent {
		t.Fatalf("mixed-case email verification status = %d, want %d: %s", status, http.StatusNoContent, body)
	}

	pair := loginMeTestPair(t, stack, mixedUsername, password)
	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("mixed-case GET /me status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var profile meProfileTestResponse
	decodeResponse(t, body, &profile)
	if profile.Username != "mixeduser" {
		t.Fatalf("mixed-case profile username = %q, want mixeduser", profile.Username)
	}

	upperPair := loginMeTestPair(t, stack, strings.ToUpper(mixedUsername), password)
	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, upperPair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("all-caps GET /me status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &profile)
	if profile.Username != "mixeduser" {
		t.Fatalf("all-caps profile username = %q, want mixeduser", profile.Username)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/me", map[string]string{"username": "MixedCase2"}, pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("mixed-case username PATCH /me status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &profile)
	if profile.Username != "mixedcase2" {
		t.Fatalf("patched profile username = %q, want mixedcase2", profile.Username)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "alice",
		"email":    "alice-lower@example.test",
		"password": password,
	}, "")
	if status != http.StatusCreated {
		t.Fatalf("lowercase duplicate setup registration status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "ALICE",
		"email":    "alice-upper@example.test",
		"password": password,
	}, "")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("case-insensitive duplicate registration status = %d, want %d: %s", status, http.StatusUnprocessableEntity, body)
	}
}

func TestRegistrationApprovalLifecycle(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "approval")
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username":     "approval-user",
		"email":        "approval-user@example.test",
		"password":     "correct-password1",
		"display_name": "Approval User",
	}, "")
	if status != http.StatusCreated {
		t.Fatalf("approval registration status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var registered registrationResponse
	decodeResponse(t, body, &registered)
	if registered.ID == "" || registered.Status != "pending" {
		t.Fatalf("registration response = %+v, want pending user", registered)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "approval-user",
		"password": "correct-password1",
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "account_pending") {
		t.Fatalf("pending login = %d %s, want account_pending 403", status, body)
	}

	admin := seedPasswordUser(t, context.Background(), stack.database.pool, "approval-admin", "admin-password")
	bootstrapTestAdmin(t, context.Background(), stack.database.pool, admin.ID)
	adminToken := loginUser(t, stack, admin.Username, "admin-password")
	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+registered.ID+"/approve", nil, adminToken)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "email_not_verified") {
		t.Fatalf("approval before verification = %d %s, want email_not_verified 422", status, body)
	}

	token := registrationToken(t, stack, registered.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/verify-email", map[string]string{"token": token}, "")
	if status != http.StatusNoContent {
		t.Fatalf("email verification status = %d, want %d: %s", status, http.StatusNoContent, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "approval-user",
		"password": "correct-password1",
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "account_pending") {
		t.Fatalf("verified pending login = %d %s, want account_pending 403", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+registered.ID+"/approve", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("approval status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var approved registrationResponse
	decodeResponse(t, body, &approved)
	if approved.ID != registered.ID || approved.Status != "active" {
		t.Fatalf("approved user = %+v, want active user %s", approved, registered.ID)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "approval-user",
		"password": "correct-password1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("approved login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/verify-email", map[string]string{"token": token}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("verification token reuse = %d %s, want invalid_token 400", status, body)
	}
}

func TestRegistrationOpenLifecycle(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "open")
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "open-user",
		"email":    "open-user@example.test",
		"password": "correct-password1",
	}, "")
	if status != http.StatusCreated {
		t.Fatalf("open registration status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var registered registrationResponse
	decodeResponse(t, body, &registered)
	token := registrationToken(t, stack, registered.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/verify-email", map[string]string{"token": token}, "")
	if status != http.StatusNoContent {
		t.Fatalf("open email verification status = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "open-user",
		"password": "correct-password1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("open login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
}

func registrationToken(t *testing.T, stack *integrationStack, userID string) string {
	t.Helper()
	var payload []byte
	err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload
		FROM outbox
		WHERE topic = 'notify.user.verification' AND payload->>'user_id' = $1
		ORDER BY id DESC LIMIT 1`, userID).Scan(&payload)
	if err != nil {
		t.Fatalf("load verification notification: %v", err)
	}
	var notification struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &notification); err != nil {
		t.Fatalf("decode verification notification: %v", err)
	}
	if notification.Token == "" {
		t.Fatalf("verification notification has no token: %s", payload)
	}
	return notification.Token
}
