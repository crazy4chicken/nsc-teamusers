package test

import (
	"context"
	"net/http"
	"testing"
)

func TestAuthzDenyPrecedenceAndGroupBinding(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	admin := seedPasswordUser(t, ctx, stack.database.pool, "deny-admin", "DenyAdminPassword1")
	bootstrapTestAdmin(t, ctx, stack.database.pool, admin.ID)
	adminToken := loginUser(t, stack, admin.Username, "DenyAdminPassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "deny-target",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create deny target status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var target userResponse
	decodeResponse(t, body, &target)

	status, body = stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "deny-team",
		"name": "Deny Team",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create deny team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "deny-group",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create deny group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)

	for _, key := range []string{"order-deny:read:team", "!order-deny:read:team"} {
		status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "deny precedence test permission",
			"registered_by": admin.ID,
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("register %s status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]any{
		"team_id": team.ID,
		"name":    "deny-group-role",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create deny group role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"order-deny:read:team", "!order-deny:read:team"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set deny group role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "group",
		"subject_id":   group.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("bind deny group role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+group.ID+"/members", map[string]string{
		"user_id": target.ID,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("add deny target membership status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create deny check service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login deny check service status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order-deny:read:team",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("deny precedence check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var check checkResponse
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("group deny allowed an otherwise granted permission")
	}

	delegate := seedPasswordUser(t, ctx, stack.database.pool, "admin-deny-delegate", "AdminDenyDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key":           "!iam:teams:any",
		"description":   "deny administrative team access",
		"registered_by": admin.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("register admin deny status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"name": "admin-deny-role",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create admin deny role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var adminRole roleResponse
	decodeResponse(t, body, &adminRole)
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+adminRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:teams:any", "!iam:teams:any"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set admin deny role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"role_id":      adminRole.ID,
		"subject_kind": "user",
		"subject_id":   delegate.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("bind admin deny role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	delegateToken := loginUser(t, stack, delegate.Username, "AdminDenyDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/teams", nil, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("denied admin GET /teams status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}
