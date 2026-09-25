package test

import (
	"net/http"
	"testing"
)

func TestAdminAuditEndpoint(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "audit",
		"name": "Audit",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create audit team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)

	status, _ = stack.jsonRequest(t, http.MethodGet, "/audit", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("audit without token status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/audit?team_id="+team.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("filtered audit status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var auditLog auditResponse
	decodeResponse(t, body, &auditLog)
	if len(auditLog.Items) == 0 {
		t.Fatal("filtered audit returned no team mutation")
	}
	foundTeamAction := false
	for _, entry := range auditLog.Items {
		if entry.Action == "team.created" {
			foundTeamAction = true
			break
		}
	}
	if !foundTeamAction {
		t.Fatalf("filtered audit entries = %+v, want team.created", auditLog.Items)
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/audit?cursor=-1", nil, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("negative audit cursor status = %d, want %d", status, http.StatusBadRequest)
	}
}
