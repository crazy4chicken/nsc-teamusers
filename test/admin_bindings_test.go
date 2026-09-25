package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminBindingEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "bindings",
		"name": "Bindings",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, body = stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "binding-user",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var user userResponse
	decodeResponse(t, body, &user)

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "binding-group",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)

	status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key":           "shipping:read:team",
		"description":   "Read shipping",
		"registered_by": "integration",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding permission status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "shipping-reader",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding role status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"shipping:read:team"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("set binding role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "group",
		"subject_id":   group.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create group binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var binding struct {
		ID          string `json:"id"`
		RoleID      string `json:"role_id"`
		SubjectKind string `json:"subject_kind"`
		SubjectID   string `json:"subject_id"`
	}
	decodeResponse(t, body, &binding)
	if binding.ID == "" || binding.RoleID != role.ID || binding.SubjectKind != "group" || binding.SubjectID != group.ID {
		t.Fatalf("binding = %+v", binding)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=group&subject_id="+group.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list group bindings status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeResponse(t, body, &page)
	if len(page.Items) != 1 {
		t.Fatalf("binding list has %d items, want 1", len(page.Items))
	}
	status, _ = stack.jsonRequest(t, http.MethodGet, "/bindings", nil, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("bindings without subject query status = %d, want %d", status, http.StatusBadRequest)
	}

	condition := "resource.owner_id == subject.id"
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "user",
		"subject_id":   user.ID,
		"condition":    condition,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create user binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "user",
		"subject_id":   user.ID,
		"condition":    "not a valid condition",
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid binding condition status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
	status, _ = stack.jsonRequest(t, http.MethodDelete, "/bindings/"+binding.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete binding status = %d, want %d", status, http.StatusNoContent)
	}
	status, _ = stack.jsonRequest(t, http.MethodDelete, "/bindings/does-not-exist", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("delete unknown binding status = %d, want %d", status, http.StatusNotFound)
	}
}
