package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminUsersEndpoints(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)

	status, _ := stack.jsonRequest(t, http.MethodGet, "/users", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("users without token status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username":     "alice",
		"email":        "alice@example.test",
		"display_name": "Alice",
		"password":     "alice-password",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var alice struct {
		ID          string `json:"id"`
		Username    string `json:"username"`
		DisplayName string `json:"display_name"`
		Status      string `json:"status"`
	}
	decodeResponse(t, body, &alice)
	if alice.ID == "" || alice.Username != "alice" || alice.DisplayName != "Alice" || alice.Status != "active" {
		t.Fatalf("created user = %+v", alice)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+alice.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get user status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var fetched userResponse
	decodeResponse(t, body, &fetched)
	if fetched.ID != alice.ID || fetched.Username != "alice" {
		t.Fatalf("fetched user = %+v, want id %s", fetched, alice.ID)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/users/"+alice.ID, map[string]string{
		"display_name": "Alice Updated",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("patch user status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var patched struct {
		DisplayName string `json:"display_name"`
	}
	decodeResponse(t, body, &patched)
	if patched.DisplayName != "Alice Updated" {
		t.Fatalf("patched user = %+v", patched)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "bob",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create second user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var bob userResponse
	decodeResponse(t, body, &bob)

	status, body = stack.jsonRequest(t, http.MethodGet, "/users?limit=1", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("first user page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var firstPage struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	decodeResponse(t, body, &firstPage)
	if len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first user page = %+v, want one item and cursor", firstPage)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users?limit=1&cursor="+firstPage.NextCursor, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("second user page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var secondPage struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeResponse(t, body, &secondPage)
	if len(secondPage.Items) != 1 {
		t.Fatalf("second user page has %d items, want 1", len(secondPage.Items))
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/users/"+alice.ID+"/credentials", map[string]string{
		"kind": "password",
	}, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("password credential without password status = %d, want %d", status, http.StatusBadRequest)
	}
	status, _ = stack.rawRequest(t, http.MethodPost, "/users", []byte("{"), adminToken, map[string]string{
		"Content-Type": "application/json",
	})
	if status != http.StatusBadRequest {
		t.Fatalf("malformed user body status = %d, want %d", status, http.StatusBadRequest)
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/users/does-not-exist", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown user status = %d, want %d", status, http.StatusNotFound)
	}

	status, _ = stack.jsonRequest(t, http.MethodDelete, "/users/"+bob.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete user status = %d, want %d", status, http.StatusNoContent)
	}
	if bob.ID == admin.ID {
		t.Fatal("test user unexpectedly reused bootstrap user id")
	}
}
