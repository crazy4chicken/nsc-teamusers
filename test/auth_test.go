package test

import (
	"context"
	"net/http"
	"testing"
)

func TestAuthLifecycle(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()

	admin := seedPasswordUser(t, ctx, stack.database.pool, "admin", "admin-password")
	bootstrapTestAdmin(t, ctx, stack.database.pool, admin.ID)

	status, _ := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": admin.Username,
		"password": "wrong-password",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": admin.Username,
		"password": "admin-password",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var login tokenPair
	decodeResponse(t, body, &login)
	assertTokenPair(t, login)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var rotated tokenPair
	decodeResponse(t, body, &rotated)
	assertTokenPair(t, rotated)

	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("replayed refresh status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": rotated.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("family refresh after replay status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/.well-known/jwks.json", nil, "")
	if status != http.StatusOK {
		t.Fatalf("JWKS status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var jwks jwksResponse
	decodeResponse(t, body, &jwks)
	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS response has no keys")
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/users", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("admin request without token status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users", nil, login.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("admin request with token status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{
		"kind": "service",
	}, login.AccessToken)
	if status != http.StatusCreated {
		t.Fatalf("service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	if credential.ClientID != admin.Username || credential.ClientSecret == "" {
		t.Fatalf("service credential response = %+v, want client id and secret", credential)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("client credentials status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	assertTokenPair(t, servicePair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/introspect", map[string]string{
		"token": servicePair.AccessToken,
	}, servicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("service introspection status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var introspection introspectionResponse
	decodeResponse(t, body, &introspection)
	if !introspection.Active || introspection.Kind != "service" || introspection.Subject != admin.ID {
		t.Fatalf("service introspection = %+v, want active service subject %s", introspection, admin.ID)
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/introspect", map[string]string{
		"token": login.AccessToken,
	}, login.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("introspection with user token status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/introspect", map[string]string{
		"token": servicePair.AccessToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("introspection without token status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestAuthLogout(t *testing.T) {
	stack := newIntegrationStack(t)
	admin := seedPasswordUser(t, context.Background(), stack.database.pool, "admin", "admin-password")

	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": admin.Username,
		"password": "admin-password",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/logout", map[string]string{
		"refresh_token": pair.RefreshToken,
	}, "")
	if status != http.StatusNoContent {
		t.Fatalf("logout status = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": pair.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("refresh after logout status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/logout", map[string]string{}, "")
	if status != http.StatusNoContent {
		t.Fatalf("idempotent logout status = %d, want %d", status, http.StatusNoContent)
	}
}
