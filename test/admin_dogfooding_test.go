package test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAdminDogfoodingAuthorization(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()

	admin := seedPasswordUser(t, ctx, stack.database.pool, "dogfood-admin", "DogfoodAdminPassword1")
	adminToken := loginUser(t, stack, admin.Username, "DogfoodAdminPassword1")
	status, body := stack.jsonRequest(t, http.MethodGet, "/users", nil, adminToken)
	if status != http.StatusForbidden || !strings.Contains(string(body), "insufficient_permissions") {
		t.Fatalf("unprivileged admin GET /users = %d %s, want insufficient_permissions 403", status, body)
	}

	bootstrapTestAdmin(t, ctx, stack.database.pool, admin.ID)
	adminToken = loginUser(t, stack, admin.Username, "DogfoodAdminPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/users", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("bootstrapped admin GET /users = %d %s, want %d", status, body, http.StatusOK)
	}

	service := seedPasswordUser(t, ctx, stack.database.pool, "dogfood-service", "DogfoodServicePassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+service.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("service credential creation = %d %s, want %d", status, body, http.StatusCreated)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("service login = %d %s, want %d", status, body, http.StatusOK)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	status, body = stack.jsonRequest(t, http.MethodGet, "/users", nil, servicePair.AccessToken)
	if status != http.StatusForbidden {
		t.Fatalf("service GET /users = %d %s, want %d", status, body, http.StatusForbidden)
	}

	auditReader := seedPasswordUser(t, ctx, stack.database.pool, "dogfood-audit", "DogfoodAuditPassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key":           "iam:audit:any",
		"description":   "Read audit entries",
		"registered_by": admin.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("audit permission registration = %d %s, want %d", status, body, http.StatusCreated)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"name": "dogfood-audit-reader",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("audit role creation = %d %s, want %d", status, body, http.StatusCreated)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:audit:any"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("audit role permissions = %d %s, want %d", status, body, http.StatusOK)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"role_id":      role.ID,
		"subject_kind": "user",
		"subject_id":   auditReader.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("audit role binding = %d %s, want %d", status, body, http.StatusCreated)
	}
	auditToken := loginUser(t, stack, auditReader.Username, "DogfoodAuditPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/audit", nil, auditToken)
	if status != http.StatusOK {
		t.Fatalf("audit-only GET /audit = %d %s, want %d", status, body, http.StatusOK)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users", nil, auditToken)
	if status != http.StatusForbidden || !strings.Contains(string(body), "insufficient_permissions") {
		t.Fatalf("audit-only GET /users = %d %s, want insufficient_permissions 403", status, body)
	}
}
