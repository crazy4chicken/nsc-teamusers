package test

import (
	"context"
	"net/http"
	"testing"
)

func TestAuthzEndToEnd(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()

	admin := seedPasswordUser(t, ctx, stack.database.pool, "admin", "admin-password")
	adminToken := loginUser(t, stack, admin.Username, "admin-password")

	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "alice",
		"password": "alice-password",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("target user creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var target userResponse
	decodeResponse(t, body, &target)
	if target.ID == "" {
		t.Fatal("target user response has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("admin service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("admin service login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	assertTokenPair(t, servicePair)
	serviceToken := servicePair.AccessToken

	status, body = stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "orders",
		"name": "Orders",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("team creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	if team.ID == "" {
		t.Fatal("team response has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "operators",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("group creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)
	if group.ID == "" {
		t.Fatal("group response has no id")
	}

	for _, key := range []string{"order:read:team", "order:write:team", "doc:read:own"} {
		status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "integration permission",
			"registered_by": admin.ID,
		}, serviceToken)
		if status != http.StatusCreated {
			t.Fatalf("permission %s status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "operator",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("role creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	if role.ID == "" {
		t.Fatal("role response has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"order:read:team", "order:write:team", "doc:read:own"},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "group",
		"subject_id":   group.ID,
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("group binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+group.ID+"/members", map[string]string{
		"user_id": target.ID,
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("group membership status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/authz/permissions/"+target.ID, nil, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("permissions endpoint status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var permissions permissionsResponse
	decodeResponse(t, body, &permissions)
	assertPermissionKeys(t, permissions, []string{"order:read:team", "order:write:team", "doc:read:own"})

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:read:team",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("allow check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var check checkResponse
	decodeResponse(t, body, &check)
	if !check.Allow {
		t.Fatalf("order read check = %+v, want allow", check)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:delete:any",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("deny check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("order delete check allowed an ungranted permission")
	}

	// Remove the unconditional document grant before exercising the conditional
	// direct grant; otherwise the group grant would make the negative ABAC case
	// indistinguishable from a successful condition evaluation.
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"order:read:team", "order:write:team"},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("role permission narrowing status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "document-owner",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("conditional role creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var conditionalRole roleResponse
	decodeResponse(t, body, &conditionalRole)

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+conditionalRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"doc:read:own"},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("conditional role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	condition := "resource.owner_id == subject.id"
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"team_id":      team.ID,
		"role_id":      conditionalRole.ID,
		"subject_kind": "user",
		"subject_id":   target.ID,
		"condition":    condition,
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("direct conditional binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "doc:read:own",
		"context": map[string]any{
			"resource": map[string]string{"owner_id": target.ID, "team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("matching ABAC check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if !check.Allow {
		t.Fatal("matching ABAC check denied the owner")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "doc:read:own",
		"context": map[string]any{
			"resource": map[string]string{"owner_id": admin.ID, "team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("non-matching ABAC check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("non-matching ABAC check allowed a different owner")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+target.ID+"/disable", nil, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("disable user status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "alice",
		"password": "alice-password",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("disabled user login status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:read:team",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("disabled authorization check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("disabled user authorization check allowed access")
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/authz/permissions/unknown-user", nil, serviceToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown authorization user status = %d, want %d", status, http.StatusNotFound)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "invalid-permission",
	}, serviceToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid authorization permission status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:read:team",
	}, adminToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("authorization with user token status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/audit", nil, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("audit endpoint status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var auditLog auditResponse
	decodeResponse(t, body, &auditLog)
	if len(auditLog.Items) == 0 {
		t.Fatal("audit endpoint returned no mutation entries")
	}
	foundAction := false
	for _, entry := range auditLog.Items {
		if entry.Action == "team.created" || entry.Action == "permission.registered" || entry.Action == "user.disabled" {
			foundAction = true
			break
		}
	}
	if !foundAction {
		t.Fatalf("audit entries contain no expected mutation action: %+v", auditLog.Items)
	}
}
