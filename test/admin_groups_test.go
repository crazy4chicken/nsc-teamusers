package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminGroupAndMembershipEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "groups",
		"name": "Groups",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create group team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, body = stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "member",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create membership user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var member userResponse
	decodeResponse(t, body, &member)

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "backend",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)
	if group.ID == "" {
		t.Fatal("created group has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/groups/"+group.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get group status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var fetched struct {
		ID     string `json:"id"`
		TeamID string `json:"team_id"`
		Name   string `json:"name"`
	}
	decodeResponse(t, body, &fetched)
	if fetched.ID != group.ID || fetched.TeamID != team.ID || fetched.Name != "backend" {
		t.Fatalf("fetched group = %+v", fetched)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/groups/"+group.ID, map[string]string{
		"name": "backend-updated",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("patch group status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &fetched)
	if fetched.Name != "backend-updated" {
		t.Fatalf("patched group = %+v", fetched)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/groups?team_id="+team.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list groups status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var groupsPage struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeResponse(t, body, &groupsPage)
	if len(groupsPage.Items) != 1 {
		t.Fatalf("group list has %d items, want 1", len(groupsPage.Items))
	}
	status, _ = stack.jsonRequest(t, http.MethodGet, "/groups", nil, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("group list without team status = %d, want %d", status, http.StatusBadRequest)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+group.ID+"/members", map[string]string{
		"user_id":    member.ID,
		"expires_at": "2030-01-01T00:00:00Z",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("put membership status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var membership struct {
		GroupID   string `json:"group_id"`
		UserID    string `json:"user_id"`
		ExpiresAt string `json:"expires_at"`
	}
	decodeResponse(t, body, &membership)
	if membership.GroupID != group.ID || membership.UserID != member.ID || membership.ExpiresAt == "" {
		t.Fatalf("membership = %+v", membership)
	}

	status, _ = stack.jsonRequest(t, http.MethodDelete, "/groups/"+group.ID+"/members", map[string]string{
		"user_id": member.ID,
	}, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete membership body status = %d, want %d", status, http.StatusNoContent)
	}
	status, _ = stack.jsonRequest(t, http.MethodPut, "/groups/"+group.ID+"/members", map[string]string{
		"user_id": member.ID,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("recreate membership status = %d, want %d", status, http.StatusOK)
	}
	status, _ = stack.jsonRequest(t, http.MethodDelete, "/groups/"+group.ID+"/members/"+member.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete membership path status = %d, want %d", status, http.StatusNoContent)
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/groups/does-not-exist", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown group status = %d, want %d", status, http.StatusNotFound)
	}
	status, _ = stack.jsonRequest(t, http.MethodDelete, "/groups/"+group.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete group status = %d, want %d", status, http.StatusNoContent)
	}
}
