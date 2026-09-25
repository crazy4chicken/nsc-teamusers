package test

import (
	"context"
	"net/http"
	"testing"

	"teamusers/internal/store"
)

func TestAdminTeamScopedRoleMutationRestrictions(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()

	for _, key := range []string{"iam:roles:team", "iam:groups:team"} {
		status, body := stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "team-scoped role mutation test permission",
			"registered_by": "integration",
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("register %s status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "escalation-alpha",
		"name": "Escalation Alpha",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create alpha team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alpha teamResponse
	decodeResponse(t, body, &alpha)

	status, body = stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "escalation-beta",
		"name": "Escalation Beta",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create beta team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var beta teamResponse
	decodeResponse(t, body, &beta)

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]any{
		"team_id": alpha.ID,
		"name":    "team-scoped-admin",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create team-scoped admin role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var adminRole roleResponse
	decodeResponse(t, body, &adminRole)

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]any{
		"team_id": alpha.ID,
		"name":    "protected-role",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create protected role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var protectedRole roleResponse
	decodeResponse(t, body, &protectedRole)

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+adminRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:roles:team"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set team-scoped admin permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+protectedRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:groups:team"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set initial protected role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	delegate := seedPasswordUser(t, ctx, stack.database.pool, "escalation-delegate", "EscalationDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": alpha.ID,
		"name":    "escalation-members",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create alpha membership group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alphaGroup groupResponse
	decodeResponse(t, body, &alphaGroup)

	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+alphaGroup.ID+"/members", map[string]string{
		"user_id": delegate.ID,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("add delegate to alpha group status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"team_id":      alpha.ID,
		"role_id":      adminRole.ID,
		"subject_kind": "user",
		"subject_id":   delegate.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("bind team-scoped admin role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	delegateToken := loginUser(t, stack, delegate.Username, "EscalationDelegatePassword1")

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+protectedRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:users:any"},
	}, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("team-scoped any permission assignment status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
	permissions, _, err := store.ListRolePermissions(ctx, stack.database.pool, protectedRole.ID, "", 1000)
	if err != nil {
		t.Fatalf("list protected role permissions after rejected assignment: %v", err)
	}
	if len(permissions) != 1 || permissions[0] != "iam:groups:team" {
		t.Fatalf("protected role permissions after rejected assignment = %v, want [iam:groups:team]", permissions)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+protectedRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:groups:team"},
	}, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("team-scoped team permission assignment status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/roles/"+protectedRole.ID, map[string]string{
		"team_id": beta.ID,
	}, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("team-scoped role team move status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
	role, err := store.GetRole(ctx, stack.database.pool, protectedRole.ID)
	if err != nil {
		t.Fatalf("get protected role after rejected team move: %v", err)
	}
	if role.TeamID == nil || *role.TeamID != alpha.ID {
		t.Fatalf("protected role team after rejected move = %v, want %s", role.TeamID, alpha.ID)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/roles/"+protectedRole.ID, map[string]string{
		"name": "protected-role-renamed",
	}, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("team-scoped role name patch status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+protectedRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:users:any"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("platform any permission assignment status = %d, want %d: %s", status, http.StatusOK, body)
	}
}
