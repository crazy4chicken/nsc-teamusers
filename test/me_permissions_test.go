package test

import (
	"context"
	"net/http"
	"reflect"
	"testing"
	"time"
)

func TestMePermissionsReturnsEffectiveAllowKeys(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "me-permissions-target", "MePermissionsTargetPassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "me-permissions",
		"name": "Me Permissions",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create permissions team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "me-permissions-group",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create permissions group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)

	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+group.ID+"/members", map[string]string{
		"user_id": target.ID,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("add target to permissions group status = %d, want %d: %s", status, http.StatusOK, body)
	}

	permissionKeys := []string{
		"meperm:direct:own",
		"meperm:group:team",
		"meperm:denied:team",
		"!meperm:denied:team",
		"meperm:conditional:team",
		"meperm:expired:team",
	}
	for _, key := range permissionKeys {
		status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "self-service permission listing test",
			"registered_by": admin.ID,
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("register permission %q status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
	}

	createRole := func(name, teamID string, keys []string) roleResponse {
		t.Helper()
		request := map[string]any{"name": name}
		if teamID != "" {
			request["team_id"] = teamID
		}
		status, body := stack.jsonRequest(t, http.MethodPost, "/roles", request, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create role %q status = %d, want %d: %s", name, status, http.StatusCreated, body)
		}
		var role roleResponse
		decodeResponse(t, body, &role)
		status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
			"permission_keys": keys,
		}, adminToken)
		if status != http.StatusOK {
			t.Fatalf("set role %q permissions status = %d, want %d: %s", name, status, http.StatusOK, body)
		}
		return role
	}

	createBinding := func(roleID, subjectKind, subjectID, teamID, condition string, expiresAt *time.Time) {
		t.Helper()
		request := map[string]any{
			"role_id":      roleID,
			"subject_kind": subjectKind,
			"subject_id":   subjectID,
		}
		if teamID != "" {
			request["team_id"] = teamID
		}
		if condition != "" {
			request["condition"] = condition
		}
		if expiresAt != nil {
			request["expires_at"] = expiresAt.UTC().Format(time.RFC3339Nano)
		}
		status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", request, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create %s binding for %s status = %d, want %d: %s", subjectKind, subjectID, status, http.StatusCreated, body)
		}
	}

	directRole := createRole("me-permissions-direct", "", []string{"meperm:direct:own", "meperm:denied:team", "!meperm:denied:team"})
	createBinding(directRole.ID, "user", target.ID, "", "", nil)

	groupRole := createRole("me-permissions-group", team.ID, []string{"meperm:group:team"})
	createBinding(groupRole.ID, "group", group.ID, team.ID, "", nil)

	conditionalRole := createRole("me-permissions-conditional", "", []string{"meperm:conditional:team"})
	createBinding(conditionalRole.ID, "user", target.ID, "", `subject.kind == "user"`, nil)

	expiredRole := createRole("me-permissions-expired", "", []string{"meperm:expired:team"})
	expiredAt := time.Now().UTC().Add(-time.Hour)
	createBinding(expiredRole.ID, "user", target.ID, "", "", &expiredAt)

	token := loginUser(t, stack, target.Username, "MePermissionsTargetPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/me/permissions", nil, token)
	if status != http.StatusOK {
		t.Fatalf("GET /me/permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var response struct {
		Permissions []string `json:"permissions"`
	}
	decodeResponse(t, body, &response)
	want := []string{"meperm:direct:own", "meperm:group:team"}
	if !reflect.DeepEqual(response.Permissions, want) {
		t.Fatalf("GET /me/permissions returned %v, want %v", response.Permissions, want)
	}

	emptyUser := seedPasswordUser(t, ctx, stack.database.pool, "me-permissions-empty", "MePermissionsEmptyPassword1")
	emptyToken := loginUser(t, stack, emptyUser.Username, "MePermissionsEmptyPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/me/permissions", nil, emptyToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me/permissions for user without grants status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var emptyResponse struct {
		Permissions []string `json:"permissions"`
	}
	decodeResponse(t, body, &emptyResponse)
	if emptyResponse.Permissions == nil || len(emptyResponse.Permissions) != 0 {
		t.Fatalf("empty GET /me/permissions returned %v, want an empty array", emptyResponse.Permissions)
	}
}
