package test

import (
	"context"
	"net/http"
	"strings"
	"testing"
)

func TestAdminBatchUserStatus(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	first := createBatchUser(t, stack, adminToken, "batch-first")
	second := createBatchUser(t, stack, adminToken, "batch-second")

	status, body := stack.jsonRequest(t, http.MethodPost, "/users/batch", map[string]any{
		"ids": []string{first.ID, "missing-user", second.ID},
		"op":  "disable",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("disable batch status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var response struct {
		Results []struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		} `json:"results"`
	}
	decodeResponse(t, body, &response)
	if len(response.Results) != 3 {
		t.Fatalf("disable batch results = %+v, want three rows", response.Results)
	}
	if !response.Results[0].OK || response.Results[0].ID != first.ID {
		t.Fatalf("first disable result = %+v", response.Results[0])
	}
	if response.Results[1].OK || response.Results[1].Error != "not_found" {
		t.Fatalf("unknown disable result = %+v", response.Results[1])
	}
	if !response.Results[2].OK || response.Results[2].ID != second.ID {
		t.Fatalf("second disable result = %+v", response.Results[2])
	}
	assertBatchUserStatus(t, stack, adminToken, first.ID, "disabled")
	assertBatchUserStatus(t, stack, adminToken, second.ID, "disabled")

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/batch", map[string]any{
		"ids": []string{first.ID, "missing-user"},
		"op":  "enable",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("enable batch status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &response)
	if len(response.Results) != 2 || !response.Results[0].OK || response.Results[1].OK {
		t.Fatalf("enable batch results = %+v", response.Results)
	}
	assertBatchUserStatus(t, stack, adminToken, first.ID, "active")
	assertBatchUserStatus(t, stack, adminToken, second.ID, "disabled")

	var auditCount int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE action = 'user.disabled' AND target = $1`, first.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count disable audit entries: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("disable audit count = %d, want 1", auditCount)
	}
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE action = 'user.enabled' AND target = $1`, first.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count enable audit entries: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("enable audit count = %d, want 1", auditCount)
	}
}

func TestAdminBatchUserStatusLimit(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ids := make([]string, 501)
	status, _ := stack.jsonRequest(t, http.MethodPost, "/users/batch", map[string]any{
		"ids": ids,
		"op":  "disable",
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("over-limit batch status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
}

func TestAdminBatchMembers(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	team := createBatchTeam(t, stack, adminToken)
	group := createBatchGroup(t, stack, adminToken, team.ID)
	member := createBatchUser(t, stack, adminToken, "batch-member")
	before := getBatchUser(t, stack, adminToken, member.ID)

	status, body := stack.jsonRequest(t, http.MethodPost, "/groups/"+group.ID+"/members/batch", map[string]any{
		"user_ids": []string{member.ID, member.ID, "missing-user"},
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("members batch status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var response struct {
		Results []struct {
			ID    string `json:"id"`
			OK    bool   `json:"ok"`
			Error string `json:"error"`
		} `json:"results"`
	}
	decodeResponse(t, body, &response)
	if len(response.Results) != 3 || !response.Results[0].OK {
		t.Fatalf("members batch results = %+v", response.Results)
	}
	if response.Results[1].OK || response.Results[1].Error != "already_member" {
		t.Fatalf("duplicate membership result = %+v", response.Results[1])
	}
	if response.Results[2].OK || response.Results[2].Error != "not_found" {
		t.Fatalf("unknown membership result = %+v", response.Results[2])
	}
	if after := getBatchUser(t, stack, adminToken, member.ID); after.PermVer != before.PermVer+1 {
		t.Fatalf("member perm_ver = %d, want %d", after.PermVer, before.PermVer+1)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/groups/missing-group/members/batch", map[string]any{
		"user_ids": []string{member.ID},
	}, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown group members batch status = %d, want %d", status, http.StatusNotFound)
	}

	var auditCount int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE action = 'membership.created' AND target = $1`, group.ID+"/"+member.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count membership audit entries: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("membership audit count = %d, want 1", auditCount)
	}
}

func TestAdminUserCSVImport(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	csvBody := strings.Join([]string{
		"username,email,display_name,password",
		"imported,imported@example.test,Imported User,imported-password1",
		"weak,weak@example.test,Weak User,short",
		"imported,other@example.test,Duplicate User,imported-password2",
	}, "\n")
	status, body := stack.rawRequest(t, http.MethodPost, "/users/import", []byte(csvBody), adminToken, map[string]string{
		"Content-Type": "text/csv",
	})
	if status != http.StatusOK {
		t.Fatalf("CSV import status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var response struct {
		Results []struct {
			Row      int    `json:"row"`
			Username string `json:"username"`
			OK       bool   `json:"ok"`
			Error    string `json:"error"`
			ID       string `json:"id"`
		} `json:"results"`
	}
	decodeResponse(t, body, &response)
	if len(response.Results) != 3 {
		t.Fatalf("CSV import results = %+v", response.Results)
	}
	if response.Results[0].Row != 2 || !response.Results[0].OK || response.Results[0].ID == "" {
		t.Fatalf("happy CSV row = %+v", response.Results[0])
	}
	if response.Results[1].Row != 3 || response.Results[1].OK || response.Results[1].Error != "weak_password" {
		t.Fatalf("weak CSV row = %+v", response.Results[1])
	}
	if response.Results[2].Row != 4 || response.Results[2].OK || response.Results[2].Error != "duplicate_username" {
		t.Fatalf("duplicate CSV row = %+v", response.Results[2])
	}
	_ = loginUser(t, stack, "imported", "imported-password1")
	imported := getBatchUser(t, stack, adminToken, response.Results[0].ID)
	if imported.Status != "active" {
		t.Fatalf("imported user status = %q, want active", imported.Status)
	}

	var auditCount int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE action = 'user.created' AND target = $1`, response.Results[0].ID).Scan(&auditCount); err != nil {
		t.Fatalf("count import audit entries: %v", err)
	}
	if auditCount != 1 {
		t.Fatalf("import audit count = %d, want 1", auditCount)
	}

	status, _ = stack.rawRequest(t, http.MethodPost, "/users/import", []byte("username,email,display_name,password\nmalformed,\"unterminated"), adminToken, map[string]string{
		"Content-Type": "text/csv",
	})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("malformed CSV status = %d, want %d", status, http.StatusUnprocessableEntity)
	}
}

type batchUser struct {
	ID       string `json:"id"`
	Username string `json:"username"`
	Status   string `json:"status"`
	PermVer  int64  `json:"perm_ver"`
}

type batchTeam struct {
	ID string `json:"id"`
}

type batchGroup struct {
	ID string `json:"id"`
}

func createBatchUser(t *testing.T, stack *integrationStack, adminToken, username string) batchUser {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": username,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create batch user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var user batchUser
	decodeResponse(t, body, &user)
	return user
}

func getBatchUser(t *testing.T, stack *integrationStack, adminToken, id string) batchUser {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodGet, "/users/"+id, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get batch user status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var user batchUser
	decodeResponse(t, body, &user)
	return user
}

func assertBatchUserStatus(t *testing.T, stack *integrationStack, adminToken, id, expected string) {
	t.Helper()
	if user := getBatchUser(t, stack, adminToken, id); user.Status != expected {
		t.Fatalf("user %s status = %q, want %q", id, user.Status, expected)
	}
}

func createBatchTeam(t *testing.T, stack *integrationStack, adminToken string) batchTeam {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "batch-team",
		"name": "Batch Team",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create batch team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team batchTeam
	decodeResponse(t, body, &team)
	return team
}

func createBatchGroup(t *testing.T, stack *integrationStack, adminToken, teamID string) batchGroup {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": teamID,
		"name":    "batch-group",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create batch group status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group batchGroup
	decodeResponse(t, body, &group)
	return group
}
