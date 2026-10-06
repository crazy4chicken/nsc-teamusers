package test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"teamusers/internal/store"
)

type sessionPageTestResponse struct {
	Items      []meSessionTestResponse `json:"items"`
	NextCursor string                  `json:"next_cursor"`
}

func TestSessionPagination(t *testing.T) {
	ctx := context.Background()
	stack, _, adminToken := newAdminSession(t)
	target := seedPasswordUser(t, ctx, stack.database.pool, "page-target", "PageTargetPassword1")
	foreign := seedPasswordUser(t, ctx, stack.database.pool, "page-foreign", "PageForeignPassword1")
	empty := seedPasswordUser(t, ctx, stack.database.pool, "page-empty", "PageEmptyPassword1")
	owner := seedPasswordUser(t, ctx, stack.database.pool, "page-owner", "PageOwnerPassword1")

	createdAt := time.Now().UTC().Add(-time.Hour).Truncate(time.Microsecond)
	laterCreatedAt := createdAt.Add(time.Second)
	activeUntil := time.Now().UTC().Add(24 * time.Hour).Truncate(time.Microsecond)
	createPageTestSession(t, ctx, stack, foreign.ID, "page-foreign-session", createdAt.Add(-time.Minute), activeUntil, nil)
	createPageTestSession(t, ctx, stack, target.ID, "page-target-expired", createdAt.Add(-3*time.Second), time.Now().UTC().Add(-time.Hour), nil)
	revokedAt := time.Now().UTC().Add(-time.Minute)
	createPageTestSession(t, ctx, stack, target.ID, "page-target-revoked", createdAt.Add(-2*time.Second), activeUntil, &revokedAt)
	for _, session := range []struct {
		id        string
		createdAt time.Time
	}{
		{id: "page-target-b", createdAt: createdAt},
		{id: "page-target-a", createdAt: createdAt},
		{id: "page-target-d", createdAt: laterCreatedAt},
		{id: "page-target-c", createdAt: laterCreatedAt},
	} {
		createPageTestSession(t, ctx, stack, target.ID, session.id, session.createdAt, activeUntil, nil)
	}
	for _, session := range []struct {
		id        string
		createdAt time.Time
	}{
		{id: "page-own-b", createdAt: createdAt},
		{id: "page-own-a", createdAt: createdAt},
		{id: "page-own-c", createdAt: laterCreatedAt},
	} {
		createPageTestSession(t, ctx, stack, owner.ID, session.id, session.createdAt, activeUntil, nil)
	}
	ownerPair := loginMeTestPair(t, stack, owner.Username, "PageOwnerPassword1")

	if _, _, err := store.ListSessionsPageByUser(ctx, stack.database.pool, target.ID, "not-a-cursor", 2); !errors.Is(err, store.ErrInvalidSessionCursor) {
		t.Fatalf("malformed store cursor error = %v, want %v", err, store.ErrInvalidSessionCursor)
	}
	emptySessions, emptyNext, err := store.ListSessionsPageByUser(ctx, stack.database.pool, empty.ID, "", 2)
	if err != nil {
		t.Fatalf("list empty session page: %v", err)
	}
	if emptySessions == nil || len(emptySessions) != 0 || emptyNext != "" {
		t.Fatalf("empty store page = %+v, next %q; want non-nil empty items and no cursor", emptySessions, emptyNext)
	}

	adminPath := "/users/" + target.ID + "/sessions"
	adminPage1 := requestSessionPageTest(t, stack, adminPath, adminToken, "", 2)
	assertSessionPageIDs(t, adminPage1, "page-target-a", "page-target-b")
	if adminPage1.NextCursor == "" {
		t.Fatal("first full admin page has no next_cursor")
	}
	adminPage2 := requestSessionPageTest(t, stack, adminPath, adminToken, adminPage1.NextCursor, 2)
	assertSessionPageIDs(t, adminPage2, "page-target-c", "page-target-d")
	if adminPage2.NextCursor == "" {
		t.Fatal("full final admin page has no last-key cursor")
	}
	adminPage3 := requestSessionPageTest(t, stack, adminPath, adminToken, adminPage2.NextCursor, 2)
	if adminPage3.Items == nil || len(adminPage3.Items) != 0 || adminPage3.NextCursor != "" {
		t.Fatalf("admin follow-up page = %+v, want empty items and terminal cursor", adminPage3)
	}

	emptyPage := requestSessionPageTest(t, stack, "/users/"+empty.ID+"/sessions", adminToken, "", 2)
	if emptyPage.Items == nil || len(emptyPage.Items) != 0 || emptyPage.NextCursor != "" {
		t.Fatalf("empty admin page = %+v, want empty items and terminal cursor", emptyPage)
	}
	status, body := stack.jsonRequest(t, http.MethodGet, adminPath+"?cursor=not-a-cursor&limit=2", nil, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "cursor is not a valid session cursor") {
		t.Fatalf("malformed admin cursor = %d %s, want invalid-cursor 400", status, body)
	}
	var listed int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_log WHERE action = $1 AND target = $2`, "admin.sessions.listed", target.ID).Scan(&listed); err != nil {
		t.Fatalf("count admin session-list audit events: %v", err)
	}
	if listed != 3 {
		t.Fatalf("admin session-list audit count = %d, want one per successful page request (3)", listed)
	}

	ownPath := "/me/sessions"
	ownPage1 := requestSessionPageTest(t, stack, ownPath, ownerPair.AccessToken, "", 2)
	assertSessionPageIDs(t, ownPage1, "page-own-a", "page-own-b")
	if ownPage1.NextCursor == "" {
		t.Fatal("first full own-session page has no next_cursor")
	}
	ownPage2 := requestSessionPageTest(t, stack, ownPath, ownerPair.AccessToken, ownPage1.NextCursor, 2)
	ownerSessionID := refreshSessionID(ownerPair.RefreshToken)
	assertSessionPageIDs(t, ownPage2, "page-own-c", ownerSessionID)
	if ownPage2.NextCursor == "" {
		t.Fatal("full final own-session page has no last-key cursor")
	}
	ownPage3 := requestSessionPageTest(t, stack, ownPath, ownerPair.AccessToken, ownPage2.NextCursor, 2)
	if ownPage3.Items == nil || len(ownPage3.Items) != 0 || ownPage3.NextCursor != "" {
		t.Fatalf("own-session follow-up page = %+v, want empty items and terminal cursor", ownPage3)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, ownPath+"?cursor=not-a-cursor&limit=2", nil, ownerPair.AccessToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "cursor is not a valid session cursor") {
		t.Fatalf("malformed own-session cursor = %d %s, want invalid-cursor 400", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, ownPath+"?limit=0", nil, ownerPair.AccessToken)
	if status != http.StatusBadRequest {
		t.Fatalf("zero own-session limit = %d %s, want %d", status, body, http.StatusBadRequest)
	}

	exportUser := seedPasswordUser(t, ctx, stack.database.pool, "page-export", "PageExportPassword1")
	exportPair := loginMeTestPair(t, stack, exportUser.Username, "PageExportPassword1")
	if _, err := stack.database.pool.Exec(ctx, `
		INSERT INTO sessions (id, user_id, family_id, created_at, last_active_at, expires_at, family_not_after)
		SELECT 'page-export-' || n::text, $1, 'page-export-family-' || n::text,
		       $2::timestamptz + (n * interval '1 millisecond'), $2::timestamptz + (n * interval '1 millisecond'), $3, $3
		FROM generate_series(1, 101) AS sequence(n)`, exportUser.ID, createdAt, activeUntil); err != nil {
		t.Fatalf("create sessions for full-list export: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/me/export", nil, exportPair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("session export status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var export map[string]json.RawMessage
	decodeResponse(t, body, &export)
	var exportedSessions []meSessionTestResponse
	decodeResponse(t, export["active_sessions"], &exportedSessions)
	if len(exportedSessions) != 102 {
		t.Fatalf("exported active session count = %d, want all 102 sessions", len(exportedSessions))
	}
}

func createPageTestSession(t *testing.T, ctx context.Context, stack *integrationStack, userID, sessionID string, createdAt, expiresAt time.Time, revokedAt *time.Time) {
	t.Helper()
	if _, err := store.CreateSession(ctx, stack.database.pool, store.Session{
		ID: sessionID, UserID: userID, FamilyID: "family-" + sessionID,
		CreatedAt: createdAt, LastActiveAt: createdAt, ExpiresAt: expiresAt,
		FamilyNotAfter: expiresAt, RevokedAt: revokedAt,
	}); err != nil {
		t.Fatalf("create session %q: %v", sessionID, err)
	}
}

func requestSessionPageTest(t *testing.T, stack *integrationStack, path, bearer, cursor string, limit int) sessionPageTestResponse {
	t.Helper()
	query := url.Values{}
	query.Set("limit", strconv.Itoa(limit))
	if cursor != "" {
		query.Set("cursor", cursor)
	}
	status, body := stack.jsonRequest(t, http.MethodGet, path+"?"+query.Encode(), nil, bearer)
	if status != http.StatusOK {
		t.Fatalf("list sessions %s status = %d, want %d: %s", path, status, http.StatusOK, body)
	}
	var page sessionPageTestResponse
	decodeResponse(t, body, &page)
	if page.Items == nil {
		t.Fatalf("session page %s has null items: %s", path, body)
	}
	return page
}

func assertSessionPageIDs(t *testing.T, page sessionPageTestResponse, want ...string) {
	t.Helper()
	if len(page.Items) != len(want) {
		t.Fatalf("session page IDs = %+v, want %q", page.Items, want)
	}
	for index, id := range want {
		if page.Items[index].ID != id {
			t.Fatalf("session page ID at %d = %q, want %q; page %+v", index, page.Items[index].ID, id, page.Items)
		}
	}
}
