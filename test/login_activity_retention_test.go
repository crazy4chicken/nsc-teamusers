package test

import (
	"context"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"teamusers/internal/store"
)

func TestLoginActivitySanitizationAndRetention(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "activity-retention-user", "ActivityRetentionPassword1")
	now := time.Now().UTC()
	oldAt := now.Add(-48 * time.Hour)
	oldEntry := store.LoginActivity{
		UserID: &user.ID, AttemptedUsername: "old\nuser", UserAgent: "old\tagent",
		At: oldAt, Method: "password", Result: "failure",
	}
	if err := store.CreateLoginActivity(ctx, stack.database.pool, oldEntry); err != nil {
		t.Fatalf("insert old login activity: %v", err)
	}

	longUsername := strings.Repeat("é", 128) + "x"
	longUserAgent := strings.Repeat("a", 512) + "b"
	recentEntry := store.LoginActivity{
		UserID: &user.ID, AttemptedUsername: longUsername, UserAgent: longUserAgent,
		At: now, Method: "password", Result: "success",
	}
	if err := store.CreateLoginActivity(ctx, stack.database.pool, recentEntry); err != nil {
		t.Fatalf("insert recent login activity: %v", err)
	}

	entries, _, err := store.ListLoginActivity(ctx, stack.database.pool, user.ID, 0, 10)
	if err != nil {
		t.Fatalf("list stored login activity: %v", err)
	}
	if len(entries) != 2 {
		t.Fatalf("stored activity count = %d, want 2", len(entries))
	}
	if entries[0].AttemptedUsername != strings.Repeat("é", 128) || entries[0].UserAgent != strings.Repeat("a", 512) {
		t.Fatalf("stored long metadata = %q / %d user-agent bytes, want byte-limited values", entries[0].AttemptedUsername, len(entries[0].UserAgent))
	}
	if len(entries[0].AttemptedUsername) != 256 || len(entries[0].UserAgent) != 512 ||
		!utf8.ValidString(entries[0].AttemptedUsername) || !utf8.ValidString(entries[0].UserAgent) {
		t.Fatalf("stored metadata limits or UTF-8 validity are incorrect: username bytes=%d user-agent bytes=%d", len(entries[0].AttemptedUsername), len(entries[0].UserAgent))
	}
	if entries[1].AttemptedUsername != "olduser" || entries[1].UserAgent != "oldagent" {
		t.Fatalf("stored control-character metadata = %q / %q, want olduser / oldagent", entries[1].AttemptedUsername, entries[1].UserAgent)
	}

	cutoff := now.Add(-24 * time.Hour)
	deleted, err := store.DeleteExpiredLoginActivity(ctx, stack.database.pool, cutoff)
	if err != nil {
		t.Fatalf("delete expired login activity: %v", err)
	}
	if deleted != 1 {
		t.Fatalf("deleted activity rows = %d, want 1 expired row", deleted)
	}
	remaining, _, err := store.ListLoginActivity(ctx, stack.database.pool, user.ID, 0, 10)
	if err != nil {
		t.Fatalf("list retained login activity: %v", err)
	}
	if len(remaining) != 1 || remaining[0].Result != "success" || remaining[0].At.Before(cutoff) {
		t.Fatalf("retained activity = %+v, want only the recent success", remaining)
	}
}
