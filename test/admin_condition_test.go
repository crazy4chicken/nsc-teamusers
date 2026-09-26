package test

import (
	"context"
	"net/http"
	"testing"

	"teamusers/internal/store"
)

func TestAdminConditionalGrantUsesTargetTeamAndFailsClosed(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	admin := seedPasswordUser(t, ctx, stack.database.pool, "condition-admin", "ConditionAdminPassword1")
	bootstrapTestAdmin(t, ctx, stack.database.pool, admin.ID)
	adminToken := loginUser(t, stack, admin.Username, "ConditionAdminPassword1")

	alpha := createConditionTestTeam(t, stack, adminToken, "condition-alpha")
	beta := createConditionTestTeam(t, stack, adminToken, "condition-beta")
	delegate := seedPasswordUser(t, ctx, stack.database.pool, "conditional-delegate", "ConditionalDelegatePassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"name": "conditional-admin-role",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create conditional admin role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"iam:teams:any"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set conditional admin role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	condition := `resource.team_id == "` + alpha.ID + `" && resource.owner_id == "" && subject.kind == "user"`
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"role_id":      role.ID,
		"subject_kind": "user",
		"subject_id":   delegate.ID,
		"condition":    condition,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create conditional admin binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	delegateToken := loginUser(t, stack, delegate.Username, "ConditionalDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/teams/"+alpha.ID, nil, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("conditional grant for matching team status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/teams/"+beta.ID, nil, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("conditional grant for nonmatching team status = %d, want %d: %s", status, http.StatusForbidden, body)
	}

	broken := seedPasswordUser(t, ctx, stack.database.pool, "broken-conditional-delegate", "BrokenConditionalDelegatePassword1")
	badCondition := "resource.not_a_field == true"
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: broken.ID, Condition: &badCondition,
	}); err != nil {
		t.Fatalf("insert broken conditional binding: %v", err)
	}
	if _, err := store.BumpUserPermVer(ctx, stack.database.pool, broken.ID); err != nil {
		t.Fatalf("bump broken conditional user permission version: %v", err)
	}
	brokenToken := loginUser(t, stack, broken.Username, "BrokenConditionalDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/teams/"+alpha.ID, nil, brokenToken)
	if status != http.StatusForbidden {
		t.Fatalf("broken conditional grant status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}

func createConditionTestTeam(t *testing.T, stack *integrationStack, adminToken, slug string) teamResponse {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": slug,
		"name": slug,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create condition team %q status = %d, want %d: %s", slug, status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	return team
}
