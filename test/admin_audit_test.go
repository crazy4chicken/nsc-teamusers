package test

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"io"
	"net/http"
	"strconv"
	"strings"
	"testing"
	"time"

	"teamusers/internal/store"
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

func TestAdminAuditCursorPagination(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	targetTeamID := createPaginationTeam(t, stack, adminToken, "audit-cursor")
	otherTeamID := createPaginationTeam(t, stack, adminToken, "audit-cursor-other")
	ctx := context.Background()
	targetTeam := targetTeamID
	for index := range 3 {
		if _, err := store.AppendAuditLog(ctx, stack.database.pool, store.AuditEntry{
			TeamID: &targetTeam,
			Action: "pagination.audit." + strconv.Itoa(index),
			Target: "target",
		}); err != nil {
			t.Fatalf("append target audit row %d: %v", index, err)
		}
	}
	otherTeam := otherTeamID
	if _, err := store.AppendAuditLog(ctx, stack.database.pool, store.AuditEntry{
		TeamID: &otherTeam,
		Action: "pagination.audit.foreign",
		Target: "foreign",
	}); err != nil {
		t.Fatalf("append foreign audit row: %v", err)
	}

	for _, cursor := range []string{"not-a-number", "-1", "9223372036854775808"} {
		status, body := stack.jsonRequest(t, http.MethodGet, "/audit?team_id="+targetTeamID+"&cursor="+cursor, nil, adminToken)
		if status != http.StatusBadRequest {
			t.Fatalf("audit cursor %q status = %d, want %d: %s", cursor, status, http.StatusBadRequest, body)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodGet, "/audit?team_id="+targetTeamID+"&limit=0", nil, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("zero audit limit status = %d, want %d: %s", status, http.StatusBadRequest, body)
	}

	type auditPageItem struct {
		ID     int64  `json:"id"`
		TeamID string `json:"team_id"`
		Action string `json:"action"`
	}
	type auditPage struct {
		Items      []auditPageItem `json:"items"`
		NextCursor string          `json:"next_cursor"`
	}
	requestPage := func(limit int, cursor string) auditPage {
		t.Helper()
		path := "/audit?team_id=" + targetTeamID + "&limit=" + strconv.Itoa(limit) + "&cursor=" + cursor
		status, body := stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
		if status != http.StatusOK {
			t.Fatalf("audit page status = %d, want %d: %s", status, http.StatusOK, body)
		}
		var page auditPage
		decodeResponse(t, body, &page)
		return page
	}

	first := requestPage(2, "0")
	if len(first.Items) != 2 || first.NextCursor == "" {
		t.Fatalf("first full audit page = %+v, want two items and a cursor", first)
	}
	if first.NextCursor != strconv.FormatInt(first.Items[1].ID, 10) {
		t.Fatalf("first audit next_cursor = %q, want final row ID %d as a string", first.NextCursor, first.Items[1].ID)
	}
	second := requestPage(2, first.NextCursor)
	if len(second.Items) != 2 || second.NextCursor == "" {
		t.Fatalf("second full audit page = %+v, want two items and a cursor", second)
	}
	if second.NextCursor != strconv.FormatInt(second.Items[1].ID, 10) {
		t.Fatalf("second audit next_cursor = %q, want final row ID %d as a string", second.NextCursor, second.Items[1].ID)
	}
	allItems := append(append([]auditPageItem(nil), first.Items...), second.Items...)
	if len(allItems) != 4 {
		t.Fatalf("filtered audit item count = %d, want 4", len(allItems))
	}
	for index, item := range allItems {
		if item.TeamID != targetTeamID {
			t.Fatalf("filtered audit row %d has team_id %q, want %q", item.ID, item.TeamID, targetTeamID)
		}
		if index > 0 && item.ID <= allItems[index-1].ID {
			t.Fatalf("audit IDs are not strictly ascending: %d then %d", allItems[index-1].ID, item.ID)
		}
	}
	terminal := requestPage(2, second.NextCursor)
	if terminal.Items == nil || len(terminal.Items) != 0 || terminal.NextCursor != "" {
		t.Fatalf("exact-full-page follow-up = %+v, want empty items and terminal cursor", terminal)
	}

	shortFirst := requestPage(3, "0")
	if len(shortFirst.Items) != 3 || shortFirst.NextCursor == "" {
		t.Fatalf("short-page walk first result = %+v, want three items and a cursor", shortFirst)
	}
	shortFinal := requestPage(3, shortFirst.NextCursor)
	if shortFinal.Items == nil || len(shortFinal.Items) != 1 || shortFinal.NextCursor != "" {
		t.Fatalf("short final audit page = %+v, want one item and terminal cursor", shortFinal)
	}
}
