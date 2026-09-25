package test

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

func TestMeEmailChangeLifecycle(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "lifecycle-email", "Lifecycle-password1")
	oldEmail := "old-lifecycle@example.test"
	user = setLifecycleEmail(t, stack.database.pool, user, oldEmail)
	pair := loginMeTestPair(t, stack, user.Username, "Lifecycle-password1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/me/email", map[string]string{
		"new_email": "new-lifecycle@example.test",
		"password":  "wrong-password1",
	}, pair.AccessToken)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_credentials") {
		t.Fatalf("wrong email-change password = %d %s, want invalid_credentials 401", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/email", map[string]string{
		"new_email": "new-lifecycle@example.test",
		"password":  "Lifecycle-password1",
	}, pair.AccessToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("request email change = %d %q, want empty 204", status, body)
	}
	var notification struct {
		UserID   string `json:"user_id"`
		NewEmail string `json:"new_email"`
		Token    string `json:"token"`
	}
	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload FROM outbox
		WHERE topic = 'notify.email.change_verification' AND payload->>'user_id' = $1
		ORDER BY id DESC LIMIT 1`, user.ID).Scan(&payload); err != nil {
		t.Fatalf("read email-change notification: %v", err)
	}
	decodeResponse(t, payload, &notification)
	if notification.UserID != user.ID || notification.NewEmail != "new-lifecycle@example.test" || notification.Token == "" {
		t.Fatalf("email-change notification = %+v", notification)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/email/confirm", map[string]string{
		"token": "not-a-token",
	}, pair.AccessToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("bad email-change token = %d %s, want invalid_token 400", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/email/confirm", map[string]string{
		"token": notification.Token,
	}, pair.AccessToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("confirm email change = %d %q, want empty 204", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/email/confirm", map[string]string{
		"token": notification.Token,
	}, pair.AccessToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("reused email-change token = %d %s, want invalid_token 400", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("profile after email change = %d: %s", status, body)
	}
	var profile meProfileTestResponse
	decodeResponse(t, body, &profile)
	if profile.Email == nil || *profile.Email != "new-lifecycle@example.test" || profile.EmailVerifiedAt == nil {
		t.Fatalf("profile after email change = %+v", profile)
	}
	if _, err := store.GetUserByEmail(context.Background(), stack.database.pool, oldEmail); !errors.Is(err, pgx.ErrNoRows) {
		t.Fatalf("old email lookup error = %v, want no rows", err)
	}
	newPair := loginMeTestPair(t, stack, user.Username, "Lifecycle-password1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, newPair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("login/profile after email change = %d: %s", status, body)
	}
	decodeResponse(t, body, &profile)
	if profile.Email == nil || *profile.Email != "new-lifecycle@example.test" || profile.EmailVerifiedAt == nil {
		t.Fatalf("profile after re-login = %+v", profile)
	}
}

func TestMeDeleteAnonymizesAndRevokes(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "lifecycle-delete", "Delete-password1")
	user = setLifecycleEmail(t, stack.database.pool, user, "delete-lifecycle@example.test")
	pair := loginMeTestPair(t, stack, user.Username, "Delete-password1")
	for _, kind := range []string{"service", "totp", "totp_pending", "backup_codes", "passkeys"} {
		if _, err := store.CreateCredential(context.Background(), stack.database.pool, store.Credential{
			UserID: user.ID,
			Kind:   kind,
			Hash:   "credential-material-" + kind,
		}); err != nil {
			t.Fatalf("create %s credential: %v", kind, err)
		}
	}

	status, body := stack.jsonRequest(t, http.MethodDelete, "/me", map[string]string{
		"password": "wrong-password1",
	}, pair.AccessToken)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_credentials") {
		t.Fatalf("wrong erasure password = %d %s, want invalid_credentials 401", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodDelete, "/me", map[string]string{
		"password": "Delete-password1",
	}, pair.AccessToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("erase account = %d %q, want empty 204", status, body)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "Delete-password1",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("login after erasure = %d, want 401", status)
	}
	status, _ = stack.jsonRequest(t, http.MethodGet, "/me", nil, pair.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("GET /me with pre-erasure token = %d, want 401", status)
	}

	erased, err := store.GetUser(context.Background(), stack.database.pool, user.ID)
	if err != nil {
		t.Fatalf("read erased user: %v", err)
	}
	if !strings.HasPrefix(erased.Username, "deleted_") || erased.Email == nil ||
		!strings.HasPrefix(*erased.Email, "deleted_") || !strings.HasSuffix(*erased.Email, "@deleted.invalid") ||
		erased.DisplayName != "" || erased.Status != "disabled" {
		t.Fatalf("erased user = %+v", erased)
	}
	var credentialCount, activeSessionCount int
	if err := stack.database.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM credentials WHERE user_id = $1`, user.ID).Scan(&credentialCount); err != nil {
		t.Fatalf("count erased credentials: %v", err)
	}
	if credentialCount != 0 {
		t.Fatalf("erased credential count = %d, want 0", credentialCount)
	}
	if err := stack.database.pool.QueryRow(context.Background(),
		`SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, user.ID).Scan(&activeSessionCount); err != nil {
		t.Fatalf("count erased sessions: %v", err)
	}
	if activeSessionCount != 0 {
		t.Fatalf("erased active session count = %d, want 0", activeSessionCount)
	}
}

func TestMeExportShape(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "lifecycle-export", "Export-password1")
	user = setLifecycleEmail(t, stack.database.pool, user, "export-lifecycle@example.test")
	team, err := store.CreateTeam(context.Background(), stack.database.pool, store.Team{
		Slug: "export-team-" + store.NewID(), Name: "Export Team", Status: "active",
	})
	if err != nil {
		t.Fatalf("create export team: %v", err)
	}
	group, err := store.CreateGroup(context.Background(), stack.database.pool, store.Group{
		TeamID: team.ID, Name: "export-group",
	})
	if err != nil {
		t.Fatalf("create export group: %v", err)
	}
	if err := store.PutMembership(context.Background(), stack.database.pool, store.Membership{
		TeamID: team.ID, GroupID: group.ID, UserID: user.ID,
	}); err != nil {
		t.Fatalf("create export membership: %v", err)
	}
	pair := loginMeTestPair(t, stack, user.Username, "Export-password1")

	if _, err := store.CreateCredential(context.Background(), stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "service", Hash: "service-secret",
	}); err != nil {
		t.Fatalf("create export service credential: %v", err)
	}
	if _, err := store.CreateCredential(context.Background(), stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "totp", Hash: "totp-seed",
	}); err != nil {
		t.Fatalf("create export TOTP credential: %v", err)
	}

	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, stack.baseURL+"/me/export", nil)
	if err != nil {
		t.Fatalf("build export request: %v", err)
	}
	request.Header.Set("Authorization", "Bearer "+pair.AccessToken)
	response, err := stack.client.Do(request)
	if err != nil {
		t.Fatalf("perform export request: %v", err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read export response: %v", err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("export status = %d: %s", response.StatusCode, body)
	}
	if !strings.Contains(response.Header.Get("Content-Disposition"), "attachment") {
		t.Fatalf("export Content-Disposition = %q", response.Header.Get("Content-Disposition"))
	}
	var export map[string]json.RawMessage
	decodeResponse(t, body, &export)
	for _, key := range []string{"profile", "memberships", "effective_permissions", "active_sessions", "totp_enabled", "passkey_count"} {
		if _, ok := export[key]; !ok {
			t.Fatalf("export missing top-level key %q: %s", key, body)
		}
	}
	var profile map[string]json.RawMessage
	decodeResponse(t, export["profile"], &profile)
	for _, key := range []string{"id", "username", "email", "display_name", "status", "email_verified_at", "created_at"} {
		if _, ok := profile[key]; !ok {
			t.Fatalf("export profile missing key %q: %s", key, export["profile"])
		}
	}
	var memberships []map[string]json.RawMessage
	decodeResponse(t, export["memberships"], &memberships)
	if len(memberships) != 1 {
		t.Fatalf("export memberships = %s", export["memberships"])
	}
	if _, ok := memberships[0]["group_id"]; !ok {
		t.Fatal("export membership missing group_id")
	}
	if _, ok := memberships[0]["team_id"]; !ok {
		t.Fatal("export membership missing team_id")
	}
	if strings.Contains(string(body), "service-secret") || strings.Contains(string(body), "totp-seed") ||
		strings.Contains(string(body), "credential") || strings.Contains(string(body), "password") || strings.Contains(string(body), "hash") {
		t.Fatalf("export contains credential material: %s", body)
	}
	var totpEnabled bool
	decodeResponse(t, export["totp_enabled"], &totpEnabled)
	if !totpEnabled {
		t.Fatal("export totp_enabled = false, want true")
	}
}

func setLifecycleEmail(t *testing.T, q store.Q, user store.User, email string) store.User {
	t.Helper()
	user.Email = &email
	updated, err := store.UpdateUser(context.Background(), q, user)
	if err != nil {
		t.Fatalf("set lifecycle email: %v", err)
	}
	return updated
}
