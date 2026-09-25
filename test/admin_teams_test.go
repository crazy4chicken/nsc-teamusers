package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminTeamEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "alpha",
		"name": "Alpha",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alpha teamResponse
	decodeResponse(t, body, &alpha)
	if alpha.ID == "" {
		t.Fatal("created team has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug":   "beta",
		"name":   "Beta",
		"status": "active",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create second team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var beta teamResponse
	decodeResponse(t, body, &beta)

	status, body = stack.jsonRequest(t, http.MethodGet, "/teams/"+alpha.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get team status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var fetched struct {
		ID     string `json:"id"`
		Slug   string `json:"slug"`
		Status string `json:"status"`
	}
	decodeResponse(t, body, &fetched)
	if fetched.ID != alpha.ID || fetched.Slug != "alpha" || fetched.Status != "active" {
		t.Fatalf("fetched team = %+v", fetched)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+alpha.ID, map[string]string{
		"name":   "Alpha Updated",
		"status": "disabled",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("patch team status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var patched struct {
		Name   string `json:"name"`
		Status string `json:"status"`
	}
	decodeResponse(t, body, &patched)
	if patched.Name != "Alpha Updated" || patched.Status != "disabled" {
		t.Fatalf("patched team = %+v", patched)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/teams?limit=1", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("first team page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var firstPage struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	decodeResponse(t, body, &firstPage)
	if len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first team page = %+v, want one item and cursor", firstPage)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/teams?limit=1&cursor="+firstPage.NextCursor, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("second team page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var secondPage struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeResponse(t, body, &secondPage)
	if len(secondPage.Items) != 1 {
		t.Fatalf("second team page has %d items, want 1", len(secondPage.Items))
	}

	status, _ = stack.jsonRequest(t, http.MethodPatch, "/teams/"+alpha.ID, map[string]string{}, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("empty team patch status = %d, want %d", status, http.StatusBadRequest)
	}
	status, _ = stack.jsonRequest(t, http.MethodGet, "/teams/does-not-exist", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown team status = %d, want %d", status, http.StatusNotFound)
	}

	status, _ = stack.jsonRequest(t, http.MethodDelete, "/teams/"+beta.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete team status = %d, want %d", status, http.StatusNoContent)
	}
}
