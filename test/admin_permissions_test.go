package test

import (
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminPermissionEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	request := map[string]string{
		"key":           "payment:read:team",
		"description":   "Read payments",
		"registered_by": "integration",
	}
	headers := map[string]string{"Idempotency-Key": "permission-replay-1"}

	status, body := stack.jsonRequestHeaders(t, http.MethodPost, "/permissions", request, adminToken, headers)
	if status != http.StatusCreated {
		t.Fatalf("register permission status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var permission struct {
		Key          string `json:"key"`
		Description  string `json:"description"`
		RegisteredBy string `json:"registered_by"`
	}
	decodeResponse(t, body, &permission)
	if permission.Key != request["key"] || permission.Description != request["description"] || permission.RegisteredBy != request["registered_by"] {
		t.Fatalf("permission = %+v", permission)
	}

	status, replayBody := stack.jsonRequestHeaders(t, http.MethodPost, "/permissions", request, adminToken, headers)
	if status != http.StatusCreated {
		t.Fatalf("permission replay status = %d, want %d: %s", status, http.StatusCreated, replayBody)
	}
	if string(replayBody) != string(body) {
		t.Fatalf("permission replay response differs:\nfirst %s\nreplay %s", body, replayBody)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/permissions", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var page struct {
		Items []json.RawMessage `json:"items"`
	}
	decodeResponse(t, body, &page)
	if len(page.Items) != len(testBootstrapAdminPermissionKeys)+1 {
		t.Fatalf("permission list has %d items, want bootstrap keys plus one after replay", len(page.Items))
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key":           "invalid-permission",
		"registered_by": "integration",
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("invalid permission status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
	status, _ = stack.jsonRequest(t, http.MethodGet, "/permissions", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("permissions without token status = %d, want %d", status, http.StatusUnauthorized)
	}
}
