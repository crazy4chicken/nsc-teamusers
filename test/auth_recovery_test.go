package test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"teamusers/internal/authn"
	"teamusers/internal/store"
)

func TestPasswordRecoveryRequestAndConfirm(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedRecoveryUser(t, context.Background(), stack.database.pool, "recovery-user", "recovery-user@example.test", "OldRecoveryPassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/request", map[string]string{"login": "unknown-recovery-user"}, "")
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("unknown recovery request = %d %q, want empty 204", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "OldRecoveryPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("old-password login = %d: %s", status, body)
	}
	var oldPair tokenPair
	decodeResponse(t, body, &oldPair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/request", map[string]string{"login": "recovery-user@example.test"}, "")
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("known recovery request = %d %q, want empty 204", status, body)
	}
	token := passwordResetToken(t, stack, user.ID)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/confirm", map[string]string{
		"token":        "wrong-reset-token",
		"new_password": "NewRecoveryPassword2",
	}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("wrong password reset token = %d %s, want invalid_token 400", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/confirm", map[string]string{
		"token":        token,
		"new_password": "NewRecoveryPassword2",
	}, "")
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("password reset confirm = %d %q, want empty 204", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": oldPair.RefreshToken}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("old refresh after password reset = %d %s, want 401", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "NewRecoveryPassword2",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("new-password login = %d: %s", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/confirm", map[string]string{
		"token":        token,
		"new_password": "AnotherRecoveryPassword3",
	}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("reused password reset = %d %s, want invalid_token 400", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/request", map[string]string{"login": user.Username}, "")
	if status != http.StatusNoContent {
		t.Fatalf("weak-password reset request = %d: %s", status, body)
	}
	weakToken := passwordResetToken(t, stack, user.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/confirm", map[string]string{
		"token":        weakToken,
		"new_password": "short1",
	}, "")
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("weak password reset = %d %s, want weak_password 422", status, body)
	}
}

func TestBackupCodeRegeneration(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedRecoveryUser(t, context.Background(), stack.database.pool, "backup-recovery-user", "backup-recovery@example.test", "BackupRecoveryPassword1")
	accessToken := loginUser(t, stack, user.Username, "BackupRecoveryPassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/me/totp/enroll", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("TOTP enrollment = %d: %s", status, body)
	}
	var enrollment totpEnrollResponse
	decodeResponse(t, body, &enrollment)
	code, err := authn.TOTPCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate TOTP confirmation code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/confirm", map[string]string{"code": code}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("TOTP confirmation = %d: %s", status, body)
	}
	var original backupCodesResponse
	decodeResponse(t, body, &original)

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/backup-codes", map[string]string{"password": "wrong-password1"}, accessToken)
	if status != http.StatusUnauthorized || !strings.Contains(string(body), "invalid_credentials") {
		t.Fatalf("wrong backup-code password = %d %s, want invalid_credentials 401", status, body)
	}

	noMFAUser := seedRecoveryUser(t, context.Background(), stack.database.pool, "no-mfa-recovery-user", "no-mfa-recovery@example.test", "NoMFARecoveryPassword1")
	noMFAAccess := loginUser(t, stack, noMFAUser.Username, "NoMFARecoveryPassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/backup-codes", map[string]string{"password": "NoMFARecoveryPassword1"}, noMFAAccess)
	if status != http.StatusNotFound || !strings.Contains(string(body), "mfa_not_enrolled") {
		t.Fatalf("backup-code regeneration without TOTP = %d %s, want mfa_not_enrolled 404", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/backup-codes", map[string]string{"password": "BackupRecoveryPassword1"}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("backup-code regeneration = %d: %s", status, body)
	}
	var regenerated backupCodesResponse
	decodeResponse(t, body, &regenerated)
	if len(regenerated.BackupCodes) != 10 {
		t.Fatalf("regenerated backup-code count = %d, want 10", len(regenerated.BackupCodes))
	}
	oldCodes := make(map[string]struct{}, len(original.BackupCodes))
	for _, value := range original.BackupCodes {
		oldCodes[value] = struct{}{}
	}
	for _, value := range regenerated.BackupCodes {
		if _, exists := oldCodes[value]; exists {
			t.Fatalf("regenerated backup code %q was present in old set", value)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "BackupRecoveryPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("MFA challenge after regeneration = %d: %s", status, body)
	}
	var challenge mfaChallengeResponse
	decodeResponse(t, body, &challenge)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      original.BackupCodes[0],
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("old backup code after regeneration = %d %s, want 401", status, body)
	}
}

func TestAdminTOTPReset(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	target := seedRecoveryUser(t, context.Background(), stack.database.pool, "admin-mfa-target", "admin-mfa-target@example.test", "AdminMFATargetPassword1")
	targetAccess := loginUser(t, stack, target.Username, "AdminMFATargetPassword1")

	status, body := stack.jsonRequest(t, http.MethodDelete, "/users/does-not-exist/totp", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown admin TOTP reset = %d %s, want 404", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/enroll", nil, targetAccess)
	if status != http.StatusOK {
		t.Fatalf("target TOTP enrollment = %d: %s", status, body)
	}
	var enrollment totpEnrollResponse
	decodeResponse(t, body, &enrollment)
	code, err := authn.TOTPCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate target TOTP code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/confirm", map[string]string{"code": code}, targetAccess)
	if status != http.StatusOK {
		t.Fatalf("target TOTP confirmation = %d: %s", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+target.ID+"/totp", nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("admin TOTP reset = %d %q, want empty 204", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": target.Username,
		"password": "AdminMFATargetPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login after admin TOTP reset = %d: %s", status, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
}

func seedRecoveryUser(t *testing.T, ctx context.Context, q store.Q, username, email, password string) store.User {
	t.Helper()
	hash, err := authn.HashPassword(password)
	if err != nil {
		t.Fatalf("hash recovery password: %v", err)
	}
	user, err := store.CreateUser(ctx, q, store.User{
		Username:    username,
		Email:       &email,
		DisplayName: username,
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("create recovery user %q: %v", username, err)
	}
	if _, err := store.CreateCredential(ctx, q, store.Credential{UserID: user.ID, Kind: "password", Hash: hash}); err != nil {
		t.Fatalf("create recovery password credential %q: %v", username, err)
	}
	return user
}

func passwordResetToken(t *testing.T, stack *integrationStack, userID string) string {
	t.Helper()
	var payload []byte
	err := stack.database.pool.QueryRow(context.Background(), `
        SELECT payload
        FROM outbox
        WHERE topic = 'notify.password.reset_requested' AND payload->>'user_id' = $1
        ORDER BY id DESC LIMIT 1`, userID).Scan(&payload)
	if err != nil {
		t.Fatalf("load password reset notification: %v", err)
	}
	var notification struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &notification); err != nil {
		t.Fatalf("decode password reset notification: %v", err)
	}
	if notification.Token == "" {
		t.Fatalf("password reset notification has no token: %s", payload)
	}
	return notification.Token
}
