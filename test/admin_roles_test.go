package test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"sort"
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

func TestAdminRolePermissionsCursorPagination(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "role-permissions-pagination",
		"name": "Role Permissions Pagination",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create role permissions team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "permissions-pagination-target",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create target role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var targetRole roleResponse
	decodeResponse(t, body, &targetRole)

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "permissions-pagination-other",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create other role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var otherRole roleResponse
	decodeResponse(t, body, &otherRole)

	targetPermissionKeys := []string{
		testBootstrapAdminPermissionKeys[4],
		testBootstrapAdminPermissionKeys[0],
		testBootstrapAdminPermissionKeys[2],
		testBootstrapAdminPermissionKeys[1],
		testBootstrapAdminPermissionKeys[3],
	}
	wantPermissions := append([]string(nil), targetPermissionKeys...)
	sort.Strings(wantPermissions)
	wantPermissionSet := make(map[string]bool, len(wantPermissions))
	for _, key := range wantPermissions {
		wantPermissionSet[key] = true
	}
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+targetRole.ID+"/permissions", map[string]any{
		"permission_keys": targetPermissionKeys,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set target role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	otherPermissionKey := testBootstrapAdminPermissionKeys[5]
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+otherRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{otherPermissionKey},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set other role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	type rolePermissionsPage struct {
		Items      []string `json:"items"`
		NextCursor string   `json:"next_cursor"`
	}
	seen := make(map[string]bool, len(wantPermissions))
	cursor := ""
	lastKey := ""
	for pageNumber := range 10 {
		requestPath := "/roles/" + targetRole.ID + "/permissions?limit=2"
		if cursor != "" {
			requestPath += "&cursor=" + url.QueryEscape(cursor)
		}
		status, body = stack.jsonRequest(t, http.MethodGet, requestPath, nil, adminToken)
		if status != http.StatusOK {
			t.Fatalf("target role permission page %d status = %d, want %d: %s", pageNumber, status, http.StatusOK, body)
		}
		var page rolePermissionsPage
		decodeResponse(t, body, &page)
		if page.Items == nil {
			t.Fatalf("target role permission page %d returned null items", pageNumber)
		}
		if len(page.Items) > 2 {
			t.Fatalf("target role permission page %d returned %d items with limit 2", pageNumber, len(page.Items))
		}
		for _, key := range page.Items {
			if !wantPermissionSet[key] {
				t.Fatalf("target role permissions included unexpected key %q", key)
			}
			if seen[key] {
				t.Fatalf("target role permissions returned duplicate key %q", key)
			}
			if lastKey != "" && key <= lastKey {
				t.Fatalf("target role permissions are not in stable key order: %q after %q", key, lastKey)
			}
			seen[key] = true
			lastKey = key
		}
		if len(seen) == len(wantPermissions) {
			if page.NextCursor != "" {
				t.Fatalf("final target role permission cursor = %q, want empty", page.NextCursor)
			}
			break
		}
		if len(page.Items) != 2 {
			t.Fatalf("target role permission page %d has %d items before completion, want 2", pageNumber, len(page.Items))
		}
		if page.NextCursor == "" || page.NextCursor != page.Items[len(page.Items)-1] {
			t.Fatalf("target role permission page %d cursor = %q, want final key %q", pageNumber, page.NextCursor, page.Items[len(page.Items)-1])
		}
		cursor = page.NextCursor
	}
	if len(seen) != len(wantPermissions) {
		t.Fatalf("retrieved %d target role permissions, want %d", len(seen), len(wantPermissions))
	}
	for _, key := range wantPermissions {
		if !seen[key] {
			t.Fatalf("target role permission pagination missed key %q", key)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/roles/"+otherRole.ID+"/permissions?limit=2", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("other role permission page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var otherPage rolePermissionsPage
	decodeResponse(t, body, &otherPage)
	if otherPage.Items == nil || len(otherPage.Items) != 1 || otherPage.Items[0] != otherPermissionKey || otherPage.NextCursor != "" {
		t.Fatalf("other role permission page = %+v, want only %q with an empty cursor", otherPage, otherPermissionKey)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+targetRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("clear target role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/roles/"+targetRole.ID+"/permissions", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("empty target role permission page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var emptyPage rolePermissionsPage
	decodeResponse(t, body, &emptyPage)
	if emptyPage.Items == nil || len(emptyPage.Items) != 0 || emptyPage.NextCursor != "" {
		t.Fatalf("empty target role permission page = %+v, want an empty list and cursor", emptyPage)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/roles/does-not-exist/permissions", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown role permissions status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/roles/"+targetRole.ID+"/permissions?limit=0", nil, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("invalid role permission pagination status = %d, want %d: %s", status, http.StatusBadRequest, body)
	}
}
