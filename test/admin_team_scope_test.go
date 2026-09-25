package test

import (
	"context"
	"net/http"
	"testing"
)

func TestAdminTeamScopedPermissions(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()

	for _, key := range []string{
		"iam:teams:team",
		"iam:groups:team",
		"iam:bindings:team",
	} {
		status, body := stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "team-scoped admin permission",
			"registered_by": "integration",
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("register %s status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
	}
	status, _ := stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key":           "iam:users:team",
		"description":   "invalid platform team permission",
		"registered_by": "integration",
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("register iam:users:team status = %d, want %d", status, http.StatusUnprocessableEntity)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "delegated-alpha",
		"name": "Delegated Alpha",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create alpha team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alpha teamResponse
	decodeResponse(t, body, &alpha)

	status, body = stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "delegated-beta",
		"name": "Delegated Beta",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create beta team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var beta teamResponse
	decodeResponse(t, body, &beta)

	delegate := seedPasswordUser(t, ctx, stack.database.pool, "delegated-admin", "DelegatedAdminPassword1")
	target := seedPasswordUser(t, ctx, stack.database.pool, "delegated-target", "DelegatedTargetPassword1")

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]any{
		"team_id": alpha.ID,
		"name":    "alpha-delegated-admin",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create alpha role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alphaRole roleResponse
	decodeResponse(t, body, &alphaRole)

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]any{
		"team_id": beta.ID,
		"name":    "beta-role",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create beta role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var betaRole roleResponse
	decodeResponse(t, body, &betaRole)

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+alphaRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{
			"iam:teams:team",
			"iam:groups:team",
			"iam:bindings:team",
		},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set alpha role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": alpha.ID,
		"name":    "alpha-members",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create alpha group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alphaGroup groupResponse
	decodeResponse(t, body, &alphaGroup)

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": beta.ID,
		"name":    "beta-members",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create beta group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var betaGroup groupResponse
	decodeResponse(t, body, &betaGroup)

	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+alphaGroup.ID+"/members", map[string]string{
		"user_id": delegate.ID,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("add delegated admin membership status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"team_id":      alpha.ID,
		"role_id":      alphaRole.ID,
		"subject_kind": "user",
		"subject_id":   delegate.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("bind alpha role status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	delegateToken := loginUser(t, stack, delegate.Username, "DelegatedAdminPassword1")
	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+alpha.ID, map[string]string{
		"name": "Delegated Alpha Updated",
	}, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("team-scoped PATCH alpha status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+beta.ID, map[string]string{
		"name": "Should Not Change",
	}, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("team-scoped PATCH beta status = %d, want %d: %s", status, http.StatusForbidden, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/groups/"+betaGroup.ID, map[string]string{
		"name": "Should Not Change",
	}, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("team-scoped PATCH beta group status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
	// NOTE: mutating a group the delegate belongs to bumps their perm_ver, so
	// the token must be refreshed before further delegate requests.
	status, body = stack.jsonRequest(t, http.MethodPatch, "/groups/"+alphaGroup.ID, map[string]string{
		"name": "Alpha Members Updated",
	}, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("team-scoped PATCH alpha group status = %d, want %d: %s", status, http.StatusOK, body)
	}
	delegateToken = loginUser(t, stack, delegate.Username, "DelegatedAdminPassword1")

	status, body = stack.jsonRequest(t, http.MethodGet, "/users", nil, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("team-scoped GET users status = %d, want %d: %s", status, http.StatusForbidden, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"role_id":      alphaRole.ID,
		"subject_kind": "user",
		"subject_id":   target.ID,
	}, delegateToken)
	if status != http.StatusCreated {
		t.Fatalf("team-scoped binding in alpha status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"role_id":      betaRole.ID,
		"subject_kind": "user",
		"subject_id":   target.ID,
	}, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("team-scoped binding in beta status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}
