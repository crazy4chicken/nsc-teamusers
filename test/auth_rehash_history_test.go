package test

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"testing"
	"time"

	"golang.org/x/crypto/argon2"

	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

func TestLoginRehashRecordsNewPasswordHistoryAtRotationTime(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	password := "RehashPasswordWithDigit1"
	user := seedPasswordUser(t, ctx, stack.database.pool, "rehash-history", password)

	historyCount := 2
	if _, err := store.CreatePasswordPolicy(ctx, stack.database.pool, store.PasswordPolicy{
		Name: "rehash history", Priority: 100, SubjectKind: "user", SubjectID: user.ID, HistoryCount: &historyCount,
	}); err != nil {
		t.Fatalf("create history policy: %v", err)
	}

	credential, err := store.GetCredential(ctx, stack.database.pool, user.ID, "password")
	if err != nil {
		t.Fatalf("load password credential: %v", err)
	}
	legacyHash := legacyPasswordHash(password)
	rotatedAt := time.Now().UTC().Add(-time.Hour)
	credential.Hash = legacyHash
	credential.RotatedAt = &rotatedAt
	if _, err := store.UpdateCredential(ctx, stack.database.pool, credential); err != nil {
		t.Fatalf("set legacy password hash: %v", err)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username, "password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login with legacy hash status = %d, want %d: %s", status, http.StatusOK, body)
	}

	credential, err = store.GetCredential(ctx, stack.database.pool, user.ID, "password")
	if err != nil {
		t.Fatalf("load rehashed password credential: %v", err)
	}
	if credential.Hash == legacyHash || passwd.NeedsRehash(credential.Hash) {
		t.Fatal("login did not upgrade the legacy Argon2 hash")
	}
	if credential.RotatedAt == nil {
		t.Fatal("rehash did not set credential rotation time")
	}
	historyHashes, err := store.ListPasswordHistoryHashes(ctx, stack.database.pool, user.ID, historyCount)
	if err != nil {
		t.Fatalf("load password history: %v", err)
	}
	if !passwd.PasswordInHistory(password, historyHashes, "") {
		t.Fatal("rehash did not add the new credential hash to password history")
	}
	var historySetAt time.Time
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT set_at FROM password_history WHERE user_id = $1 AND hash = $2`, user.ID, credential.Hash).Scan(&historySetAt); err != nil {
		t.Fatalf("load history set time: %v", err)
	}
	if !historySetAt.Equal(*credential.RotatedAt) {
		t.Fatalf("history set_at = %s, credential rotated_at = %s", historySetAt, *credential.RotatedAt)
	}
}

func legacyPasswordHash(password string) string {
	salt := []byte("legacy-password1")
	key := argon2.IDKey([]byte(password), salt, 2, 32*1024, 1, 32)
	encoding := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=32768,t=2,p=1$%s$%s", encoding.EncodeToString(salt), encoding.EncodeToString(key))
}
