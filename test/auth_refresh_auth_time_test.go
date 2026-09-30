package test

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	"teamusers/internal/store"
)

func TestRefreshPreservesAndDoesNotInventAuthTime(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "refresh-target", "refresh-password1")

	permissionKey := "reports:read:own"
	if _, err := store.CreatePermission(ctx, stack.database.pool, store.Permission{
		Key: permissionKey, Description: "refresh freshness integration", RegisteredBy: "integration",
	}); err != nil {
		t.Fatalf("create permission: %v", err)
	}
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "refresh-freshness"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if err := store.SetRolePermissions(ctx, stack.database.pool, role.ID, []string{permissionKey}); err != nil {
		t.Fatalf("set role permissions: %v", err)
	}
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: target.ID,
	}); err != nil {
		t.Fatalf("bind role to target: %v", err)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{"kind": "service"}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var serviceCredential credentialResponse
	decodeResponse(t, body, &serviceCredential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id": serviceCredential.ClientID, "client_secret": serviceCredential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("service login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	assertTokenPair(t, servicePair)

	login := func() tokenPair {
		t.Helper()
		status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
			"username": target.Username, "password": "refresh-password1",
		}, "")
		if status != http.StatusOK {
			t.Fatalf("user login status = %d, want %d: %s", status, http.StatusOK, body)
		}
		var pair tokenPair
		decodeResponse(t, body, &pair)
		assertTokenPair(t, pair)
		return pair
	}

	original := login()
	originalAuthTime := tokenAuthTime(t, original.AccessToken)
	if originalAuthTime <= 0 {
		t.Fatalf("login auth_time = %d, want a positive timestamp", originalAuthTime)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": original.RefreshToken}, "")
	if status != http.StatusOK {
		t.Fatalf("normal refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var refreshed tokenPair
	decodeResponse(t, body, &refreshed)
	assertTokenPair(t, refreshed)
	if got := tokenAuthTime(t, refreshed.AccessToken); got != originalAuthTime {
		t.Fatalf("refreshed auth_time = %d, want original %d", got, originalAuthTime)
	}

	legacy := login()
	legacyHash := sha256.Sum256([]byte(legacy.RefreshToken))
	if _, err := stack.database.pool.Exec(ctx, `
		UPDATE sessions SET client_meta = client_meta - 'auth_time' WHERE id = $1`, hex.EncodeToString(legacyHash[:])); err != nil {
		t.Fatalf("remove legacy auth_time metadata: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": legacy.RefreshToken}, "")
	if status != http.StatusOK {
		t.Fatalf("legacy refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &refreshed)
	assertTokenPair(t, refreshed)
	missingAuthTime := tokenAuthTime(t, refreshed.AccessToken)
	if missingAuthTime != 0 {
		t.Fatalf("legacy refreshed auth_time = %d, want 0", missingAuthTime)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject": target.ID, "permission": permissionKey, "auth_time": missingAuthTime, "max_auth_age_seconds": 600,
	}, servicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("legacy step-up check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var check checkResponse
	decodeResponse(t, body, &check)
	if check.Allow || check.Reason != "step_up_required" {
		t.Fatalf("legacy step-up check = %+v, want step_up_required", check)
	}
}

func tokenAuthTime(t *testing.T, raw string) int64 {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("access token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token payload: %v", err)
	}
	var claims struct {
		AuthTime int64 `json:"auth_time"`
	}
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode access token claims: %v", err)
	}
	return claims.AuthTime
}
