package test

import (
	"bufio"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"
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

	status, _ = stack.jsonRequest(t, http.MethodGet, "/audit/export", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("audit export without token status = %d, want %d", status, http.StatusUnauthorized)
	}

	request, err := http.NewRequest(http.MethodGet, stack.baseURL+"/audit/export?team_id="+team.ID, nil)
	if err != nil {
		t.Fatalf("build JSONL audit export request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+adminToken)
	response, err := stack.client.Do(request)
	if err != nil {
		t.Fatalf("request JSONL audit export: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		t.Fatalf("JSONL audit export status = %d, want %d", response.StatusCode, http.StatusOK)
	}
	if got := response.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("JSONL audit export Cache-Control = %q, want no-store", got)
	}
	if got := response.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("JSONL audit export X-Content-Type-Options = %q, want nosniff", got)
	}
	if contentType := response.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "application/x-ndjson") {
		t.Fatalf("JSONL audit export Content-Type = %q", contentType)
	}
	filename := strings.TrimPrefix(response.Header.Get("Content-Disposition"), `attachment; filename="audit-`)
	filename = strings.TrimSuffix(filename, `.jsonl"`)
	if _, err := time.Parse("2006-01-02", filename); err != nil {
		t.Fatalf("JSONL audit export filename date = %q: %v", filename, err)
	}
	scanner := bufio.NewScanner(response.Body)
	foundExportedTeam := false
	for scanner.Scan() {
		var entry struct {
			Action string `json:"action"`
			TeamID string `json:"team_id"`
		}
		if err := json.Unmarshal(scanner.Bytes(), &entry); err != nil {
			t.Fatalf("decode JSONL audit row %q: %v", scanner.Text(), err)
		}
		if entry.Action == "team.created" && entry.TeamID == team.ID {
			foundExportedTeam = true
		}
	}
	if err := scanner.Err(); err != nil {
		t.Fatalf("read JSONL audit export: %v", err)
	}
	if !foundExportedTeam {
		t.Fatal("JSONL audit export omitted the filtered team.created row")
	}

	csvRequest, err := http.NewRequest(http.MethodGet, stack.baseURL+"/audit/export?format=csv&team_id="+team.ID, nil)
	if err != nil {
		t.Fatalf("build CSV audit export request: %v", err)
	}
	csvRequest.Header.Set("Authorization", "Bearer "+adminToken)
	csvResponse, err := stack.client.Do(csvRequest)
	if err != nil {
		t.Fatalf("request CSV audit export: %v", err)
	}
	defer csvResponse.Body.Close()
	if csvResponse.StatusCode != http.StatusOK {
		t.Fatalf("CSV audit export status = %d, want %d", csvResponse.StatusCode, http.StatusOK)
	}
	if got := csvResponse.Header.Get("Cache-Control"); got != "no-store" {
		t.Fatalf("CSV audit export Cache-Control = %q, want no-store", got)
	}
	if got := csvResponse.Header.Get("X-Content-Type-Options"); got != "nosniff" {
		t.Fatalf("CSV audit export X-Content-Type-Options = %q, want nosniff", got)
	}
	if contentType := csvResponse.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/csv") {
		t.Fatalf("CSV audit export Content-Type = %q", contentType)
	}
	if disposition := csvResponse.Header.Get("Content-Disposition"); !strings.HasSuffix(disposition, `.csv"`) {
		t.Fatalf("CSV audit export Content-Disposition = %q", disposition)
	}
	csvReader := csv.NewReader(csvResponse.Body)
	header, err := csvReader.Read()
	if err != nil {
		t.Fatalf("read CSV audit export header: %v", err)
	}
	if got, want := strings.Join(header, ","), "id,team_id,actor_id,action,target,diff,request_id,at"; got != want {
		t.Fatalf("CSV audit export header = %q, want %q", got, want)
	}
	foundCSVTeam := false
	for {
		row, err := csvReader.Read()
		if err == io.EOF {
			break
		}
		if err != nil {
			t.Fatalf("read CSV audit export row: %v", err)
		}
		if len(row) != len(header) || row[1] != team.ID {
			t.Fatalf("CSV audit export row = %+v, want an 8-column row filtered to team %s", row, team.ID)
		}
		if row[3] == "team.created" {
			foundCSVTeam = true
		}
	}
	if !foundCSVTeam {
		t.Fatal("CSV audit export omitted the filtered team.created row")
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/audit/export?format=xml", nil, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("unsupported audit export format status = %d, want %d", status, http.StatusBadRequest)
	}
}
