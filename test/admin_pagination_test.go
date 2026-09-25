package test

import (
	"encoding/json"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
)

func TestAdminGroupCursorPagination(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	teamID := createPaginationTeam(t, stack, adminToken, "groups")
	expected := make(map[string]bool)
	for index := range 5 {
		status, body := stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
			"team_id": teamID,
			"name":    "page-group-" + strconv.Itoa(index),
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create paginated group %d status = %d, want %d: %s", index, status, http.StatusCreated, body)
		}
		var group groupResponse
		decodeResponse(t, body, &group)
		expected[group.ID] = true
	}
	walkCursorPageIDs(t, stack, "/groups?team_id="+url.QueryEscape(teamID), adminToken, "id", expected)
}

func TestAdminRoleCursorPagination(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	teamID := createPaginationTeam(t, stack, adminToken, "roles")
	expected := make(map[string]bool)
	for index := range 5 {
		status, body := stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
			"team_id": teamID,
			"name":    "page-role-" + strconv.Itoa(index),
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create paginated role %d status = %d, want %d: %s", index, status, http.StatusCreated, body)
		}
		var role roleResponse
		decodeResponse(t, body, &role)
		expected[role.ID] = true
	}
	walkCursorPageIDs(t, stack, "/roles?team_id="+url.QueryEscape(teamID), adminToken, "id", expected)
}

func TestAdminPermissionCursorPagination(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	expected := make(map[string]bool, len(testBootstrapAdminPermissionKeys)+5)
	for _, key := range testBootstrapAdminPermissionKeys {
		expected[key] = true
	}
	for index := range 5 {
		key := "pagepermission" + strconv.Itoa(index) + ":read:team"
		status, body := stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "cursor pagination permission",
			"registered_by": "pagination",
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create paginated permission %d status = %d, want %d: %s", index, status, http.StatusCreated, body)
		}
		expected[key] = true
	}
	walkCursorPageIDs(t, stack, "/permissions", adminToken, "key", expected)
}

func TestAdminBindingCursorPagination(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	teamID := createPaginationTeam(t, stack, adminToken, "bindings")
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "binding-page-user",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding pagination user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var user userResponse
	decodeResponse(t, body, &user)
	expected := make(map[string]bool)
	for index := range 5 {
		permissionKey := "pagebinding" + strconv.Itoa(index) + ":read:team"
		status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           permissionKey,
			"description":   "cursor pagination binding permission",
			"registered_by": "pagination",
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create binding pagination permission %d status = %d, want %d: %s", index, status, http.StatusCreated, body)
		}
		status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
			"team_id": teamID,
			"name":    "page-binding-role-" + strconv.Itoa(index),
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create binding pagination role %d status = %d, want %d: %s", index, status, http.StatusCreated, body)
		}
		var role roleResponse
		decodeResponse(t, body, &role)
		status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
			"permission_keys": []string{permissionKey},
		}, adminToken)
		if status != http.StatusOK {
			t.Fatalf("set binding pagination role permissions %d status = %d, want %d: %s", index, status, http.StatusOK, body)
		}
		status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
			"team_id":      teamID,
			"role_id":      role.ID,
			"subject_kind": "user",
			"subject_id":   user.ID,
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("create paginated binding %d status = %d, want %d: %s", index, status, http.StatusCreated, body)
		}
		var binding struct {
			ID string `json:"id"`
		}
		decodeResponse(t, body, &binding)
		expected[binding.ID] = true
	}
	walkCursorPageIDs(t, stack, "/bindings?subject_kind=user&subject_id="+url.QueryEscape(user.ID), adminToken, "id", expected)
}

func createPaginationTeam(t *testing.T, stack *integrationStack, adminToken, suffix string) string {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "pagination-" + suffix,
		"name": "Pagination " + suffix,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create pagination team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	return team.ID
}

func walkCursorPageIDs(t *testing.T, stack *integrationStack, path, bearer, field string, expected map[string]bool) {
	t.Helper()
	seen := make(map[string]bool, len(expected))
	cursor := ""
	for page := range 100 {
		requestPath := path
		if strings.Contains(requestPath, "?") {
			requestPath += "&limit=2"
		} else {
			requestPath += "?limit=2"
		}
		if cursor != "" {
			requestPath += "&cursor=" + url.QueryEscape(cursor)
		}
		status, body := stack.jsonRequest(t, http.MethodGet, requestPath, nil, bearer)
		if status != http.StatusOK {
			t.Fatalf("cursor page %d status = %d, want %d: %s", page, status, http.StatusOK, body)
		}
		var response struct {
			Items      []json.RawMessage `json:"items"`
			NextCursor string            `json:"next_cursor"`
		}
		decodeResponse(t, body, &response)
		if len(response.Items) > 2 {
			t.Fatalf("cursor page %d returned %d items with limit 2", page, len(response.Items))
		}
		for _, raw := range response.Items {
			var item map[string]any
			decodeResponse(t, raw, &item)
			value, ok := item[field].(string)
			if !ok || value == "" {
				t.Fatalf("cursor page %d item missing %s: %s", page, field, raw)
			}
			if seen[value] {
				t.Fatalf("cursor pagination returned duplicate %s %q", field, value)
			}
			seen[value] = true
		}
		if response.NextCursor == "" {
			if len(seen) != len(expected) {
				t.Fatalf("cursor pagination ended after page %d with %d items, want %d", page, len(seen), len(expected))
			}
			for value := range expected {
				if !seen[value] {
					t.Fatalf("cursor pagination missed %s %q", field, value)
				}
			}
			return
		}
		if response.NextCursor == cursor {
			t.Fatalf("cursor pagination repeated cursor %q", cursor)
		}
		cursor = response.NextCursor
	}
	t.Fatalf("cursor pagination did not terminate")
}
