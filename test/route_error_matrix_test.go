package test

import (
	"context"
	"net/http"
	"testing"
)

func TestAdminRouteErrorMatrix(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	target := seedPasswordUser(t, context.Background(), stack.database.pool, "route-matrix-target", "RouteMatrixTargetPassword1")
	nonAdminToken := loginUser(t, stack, target.Username, "RouteMatrixTargetPassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "route-matrix",
		"name": "Route Matrix",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create route-matrix team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "route-matrix-group",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create route-matrix group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)
	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "route-matrix-role",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create route-matrix role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)

	validMembersBody := map[string]string{"user_id": target.ID}
	validBindingBody := map[string]string{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "user",
		"subject_id":   target.ID,
	}
	cases := []struct {
		name   string
		method string
		path   string
		body   any
		bearer string
		want   int
	}{
		{name: "users no token", method: http.MethodGet, path: "/users/" + admin.ID, bearer: "", want: http.StatusUnauthorized},
		{name: "teams no token", method: http.MethodPatch, path: "/teams/" + team.ID, body: map[string]string{"name": "updated"}, bearer: "", want: http.StatusUnauthorized},
		{name: "groups no token", method: http.MethodPost, path: "/groups/" + group.ID + "/members", body: validMembersBody, bearer: "", want: http.StatusUnauthorized},
		{name: "bindings no token", method: http.MethodPost, path: "/bindings", body: validBindingBody, bearer: "", want: http.StatusUnauthorized},
		{name: "users non-admin", method: http.MethodGet, path: "/users/" + admin.ID, bearer: nonAdminToken, want: http.StatusForbidden},
		{name: "teams non-admin", method: http.MethodPatch, path: "/teams/" + team.ID, body: map[string]string{"name": "updated"}, bearer: nonAdminToken, want: http.StatusForbidden},
		{name: "groups non-admin", method: http.MethodPost, path: "/groups/" + group.ID + "/members", body: validMembersBody, bearer: nonAdminToken, want: http.StatusForbidden},
		{name: "bindings non-admin", method: http.MethodPost, path: "/bindings", body: validBindingBody, bearer: nonAdminToken, want: http.StatusForbidden},
		{name: "unknown user", method: http.MethodGet, path: "/users/does-not-exist", bearer: adminToken, want: http.StatusNotFound},
		{name: "unknown team", method: http.MethodPatch, path: "/teams/does-not-exist", body: map[string]string{"name": "updated"}, bearer: adminToken, want: http.StatusNotFound},
		{name: "unknown group", method: http.MethodPut, path: "/groups/does-not-exist/members", body: validMembersBody, bearer: adminToken, want: http.StatusNotFound},
		{name: "unknown binding role", method: http.MethodPost, path: "/bindings", body: map[string]string{
			"team_id":      team.ID,
			"role_id":      "does-not-exist",
			"subject_kind": "user",
			"subject_id":   target.ID,
		}, bearer: adminToken, want: http.StatusNotFound},
		{name: "wrong users method", method: http.MethodPost, path: "/users/" + admin.ID, body: map[string]string{}, bearer: adminToken, want: http.StatusMethodNotAllowed},
		{name: "wrong teams method", method: http.MethodPost, path: "/teams/" + team.ID, body: map[string]string{}, bearer: adminToken, want: http.StatusMethodNotAllowed},
		{name: "wrong groups method", method: http.MethodGet, path: "/groups/" + group.ID + "/members", bearer: adminToken, want: http.StatusMethodNotAllowed},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			status, body := stack.jsonRequest(t, tt.method, tt.path, tt.body, tt.bearer)
			if status != tt.want {
				t.Fatalf("%s %s status = %d, want %d: %s", tt.method, tt.path, status, tt.want, body)
			}
		})
	}
}
