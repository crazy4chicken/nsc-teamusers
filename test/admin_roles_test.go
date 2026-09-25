package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminRoleEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "roles",
		"name": "Roles",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create role team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key":           "invoice:read:team",
		"description":   "Read invoices",
		"registered_by": "integration",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create role permission status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "reader",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	if role.ID == "" {
		t.Fatal("created role has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/roles/"+role.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get role status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var fetched struct {
		ID     string `json:"id"`
		TeamID string `json:"team_id"`
		Name   string `json:"name"`
	}
	decodeResponse(t, body, &fetched)
	if fetched.ID != role.ID || fetched.TeamID != team.ID || fetched.Name != "reader" {
		t.Fatalf("fetched role = %+v", fetched)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/roles/"+role.ID, map[string]string{
		"name": "invoice-reader",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("patch role status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &fetched)
	if fetched.Name != "invoice-reader" {
		t.Fatalf("patched role = %+v", fetched)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/roles?team_id="+team.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list roles status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var rolesPage struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeResponse(t, body, &rolesPage)
	if len(rolesPage.Items) != 1 {
		t.Fatalf("role list has %d items, want 1", len(rolesPage.Items))
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"invoice:read:team"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var rolePermissions struct {
		RoleID      string   `json:"role_id"`
		Permissions []string `json:"permissions"`
	}
	decodeResponse(t, body, &rolePermissions)
	if rolePermissions.RoleID != role.ID || len(rolePermissions.Permissions) != 1 || rolePermissions.Permissions[0] != "invoice:read:team" {
		t.Fatalf("role permissions = %+v", rolePermissions)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("replace role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &rolePermissions)
	if len(rolePermissions.Permissions) != 0 {
		t.Fatalf("replaced role permissions = %+v, want empty", rolePermissions)
	}

	status, _ = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"invalid-permission"},
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid role permission status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{}, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid role body status = %d, want %d", status, http.StatusBadRequest)
	}
	status, _ = stack.jsonRequest(t, http.MethodGet, "/roles/does-not-exist", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown role status = %d, want %d", status, http.StatusNotFound)
	}

	status, _ = stack.jsonRequest(t, http.MethodDelete, "/roles/"+role.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete role status = %d, want %d", status, http.StatusNoContent)
	}
}
