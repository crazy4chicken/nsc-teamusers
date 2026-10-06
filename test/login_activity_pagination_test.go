package test

import (
	"context"
	"net/http"
	"strconv"
	"testing"

	"teamusers/internal/store"
)

func TestMeActivityCursorPagination(t *testing.T) {
	stack, owner, ownerToken := newAdminSession(t)
	ctx := context.Background()
	ownerActivity, _, err := store.ListLoginActivity(ctx, stack.database.pool, owner.ID, 0, 1000)
	if err != nil {
		t.Fatalf("count owner activity rows: %v", err)
	}
	targetCount := len(ownerActivity)
	if targetCount < 4 {
		targetCount = 4
	}
	if targetCount%2 != 0 {
		targetCount++
	}
	ownerID := owner.ID
	for index := len(ownerActivity); index < targetCount; index++ {
		if err := store.CreateLoginActivity(ctx, stack.database.pool, store.LoginActivity{
			UserID: &ownerID, AttemptedUsername: "owner-page-" + strconv.Itoa(index),
			Method: "password", Result: "success",
		}); err != nil {
			t.Fatalf("insert owner activity row %d: %v", index, err)
		}
	}
	foreign := seedPasswordUser(t, ctx, stack.database.pool, "activity-pagination-foreign", "ForeignActivityPassword1")
	foreignID := foreign.ID
	if err := store.CreateLoginActivity(ctx, stack.database.pool, store.LoginActivity{
		UserID: &foreignID, AttemptedUsername: foreign.Username, Method: "password", Result: "success",
	}); err != nil {
		t.Fatalf("insert foreign activity row: %v", err)
	}
	if err := store.CreateLoginActivity(ctx, stack.database.pool, store.LoginActivity{
		AttemptedUsername: "unknown-user", Method: "password", Result: "failure",
	}); err != nil {
		t.Fatalf("insert unresolved activity row: %v", err)
	}

	for _, cursor := range []string{"not-a-number", "-1", "9223372036854775808"} {
		status, body := stack.jsonRequest(t, http.MethodGet, "/me/activity?cursor="+cursor, nil, ownerToken)
		if status != http.StatusBadRequest {
			t.Fatalf("activity cursor %q status = %d, want %d: %s", cursor, status, http.StatusBadRequest, body)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodGet, "/me/activity?limit=0", nil, ownerToken)
	if status != http.StatusBadRequest {
		t.Fatalf("zero activity limit status = %d, want %d: %s", status, http.StatusBadRequest, body)
	}

	type activityPageItem struct {
		ID     int64  `json:"id"`
		UserID string `json:"user_id"`
	}
	type activityPage struct {
		Items      []activityPageItem `json:"items"`
		NextCursor string             `json:"next_cursor"`
	}
	requestPage := func(limit int, cursor string) activityPage {
		t.Helper()
		path := "/me/activity?limit=" + strconv.Itoa(limit) + "&cursor=" + cursor
		status, body := stack.jsonRequest(t, http.MethodGet, path, nil, ownerToken)
		if status != http.StatusOK {
			t.Fatalf("activity page status = %d, want %d: %s", status, http.StatusOK, body)
		}
		var page activityPage
		decodeResponse(t, body, &page)
		return page
	}

	const pageSize = 2
	cursor := "0"
	var previousID int64
	seen := 0
	for pageIndex := range targetCount / pageSize {
		page := requestPage(pageSize, cursor)
		if len(page.Items) != pageSize || page.NextCursor == "" {
			t.Fatalf("full activity page %d = %+v, want %d items and a cursor", pageIndex, page, pageSize)
		}
		lastID := page.Items[len(page.Items)-1].ID
		if page.NextCursor != strconv.FormatInt(lastID, 10) {
			t.Fatalf("activity next_cursor = %q, want final row ID %d as a string", page.NextCursor, lastID)
		}
		for _, item := range page.Items {
			if item.UserID != owner.ID {
				t.Fatalf("activity row %d has user_id %q, want only bearer user %q", item.ID, item.UserID, owner.ID)
			}
			if previousID != 0 && item.ID >= previousID {
				t.Fatalf("activity IDs are not strictly descending: %d then %d", previousID, item.ID)
			}
			previousID = item.ID
			seen++
		}
		cursor = page.NextCursor
	}
	if seen != targetCount {
		t.Fatalf("scoped activity item count = %d, want %d", seen, targetCount)
	}
	terminal := requestPage(pageSize, cursor)
	if terminal.Items == nil || len(terminal.Items) != 0 || terminal.NextCursor != "" {
		t.Fatalf("exact-full-page follow-up = %+v, want empty items and terminal cursor", terminal)
	}

	shortLimit := targetCount - 1
	shortFirst := requestPage(shortLimit, "0")
	if len(shortFirst.Items) != shortLimit || shortFirst.NextCursor == "" {
		t.Fatalf("short-page walk first result = %+v, want %d items and a cursor", shortFirst, shortLimit)
	}
	shortFinal := requestPage(shortLimit, shortFirst.NextCursor)
	if shortFinal.Items == nil || len(shortFinal.Items) != 1 || shortFinal.NextCursor != "" {
		t.Fatalf("short final activity page = %+v, want one item and terminal cursor", shortFinal)
	}
}
