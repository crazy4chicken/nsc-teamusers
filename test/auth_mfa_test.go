package test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"teamusers/internal/authn"
	"teamusers/internal/config"
)

type totpEnrollResponse struct {
	Secret     string `json:"secret"`
	OTPAuthURL string `json:"otpauth_url"`
}

type mfaChallengeResponse struct {
	MFARequired bool   `json:"mfa_required"`
	MFAToken    string `json:"mfa_token"`
}

type backupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

func TestTOTPEnrollmentConfirmAndMFALogin(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "mfa-user", "MfaPassword1")
	accessToken := loginUser(t, stack, user.Username, "MfaPassword1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/me/totp/enroll", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("TOTP enroll status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var enrollment totpEnrollResponse
	decodeResponse(t, body, &enrollment)
	if enrollment.Secret == "" || !strings.Contains(enrollment.OTPAuthURL, "otpauth://totp/teamusers:mfa-user?secret="+enrollment.Secret) {
		t.Fatalf("TOTP enrollment = %+v, want secret and otpauth URL", enrollment)
	}

	code, err := authn.TOTPCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate confirmation code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/confirm", map[string]string{"code": code}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("TOTP confirm status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var backup backupCodesResponse
	decodeResponse(t, body, &backup)
	if len(backup.BackupCodes) != 10 {
		t.Fatalf("backup code count = %d, want 10", len(backup.BackupCodes))
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/enroll", nil, accessToken)
	if status != http.StatusConflict {
		t.Fatalf("duplicate TOTP enroll status = %d, want %d: %s", status, http.StatusConflict, body)
	}
	for _, value := range backup.BackupCodes {
		if len(value) != 19 || value[4] != '-' || value[9] != '-' || value[14] != '-' {
			t.Fatalf("backup code %q has unexpected display format", value)
		}
		canonical := strings.ToLower(strings.ReplaceAll(value, "-", ""))
		if len(canonical) != 16 {
			t.Fatalf("backup code %q canonical length = %d, want 16", value, len(canonical))
		}
		for _, character := range canonical {
			if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyz0123456789", character) {
				t.Fatalf("backup code %q contains invalid character %q", value, character)
			}
		}
	}
	var storedKind, storedHash string
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT kind, hash FROM credentials WHERE user_id = $1 AND kind = 'backup_codes'`, user.ID).Scan(&storedKind, &storedHash); err != nil {
		t.Fatalf("load stored backup codes: %v", err)
	}
	if storedKind != "backup_codes" {
		t.Fatalf("stored backup credential kind = %q", storedKind)
	}
	var storedDigests []string
	if err := json.Unmarshal([]byte(storedHash), &storedDigests); err != nil {
		t.Fatalf("decode stored backup codes: %v", err)
	}
	if len(storedDigests) != 10 {
		t.Fatalf("stored backup digest count = %d, want 10", len(storedDigests))
	}
	digestSet := make(map[string]struct{}, len(storedDigests))
	for _, digest := range storedDigests {
		if len(digest) != 64 {
			t.Fatalf("stored backup digest %q length = %d, want 64", digest, len(digest))
		}
		digestSet[digest] = struct{}{}
	}
	firstDigest := sha256.Sum256([]byte(strings.ToLower(strings.ReplaceAll(backup.BackupCodes[0], "-", ""))))
	if _, ok := digestSet[hex.EncodeToString(firstDigest[:])]; !ok {
		t.Fatalf("stored backup digests do not contain first returned code")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "MfaPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("MFA challenge status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var challenge mfaChallengeResponse
	decodeResponse(t, body, &challenge)
	if !challenge.MFARequired || challenge.MFAToken == "" {
		t.Fatalf("MFA challenge = %+v, want required token", challenge)
	}

	code, err = authn.TOTPCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate login code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      code,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("TOTP MFA login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "MfaPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("backup-code challenge status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &challenge)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      backup.BackupCodes[0],
	}, "")
	if status != http.StatusOK {
		t.Fatalf("backup-code MFA login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "MfaPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("backup-code reuse challenge status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &challenge)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      backup.BackupCodes[0],
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("reused backup-code status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
}

func TestMFALockoutExpires(t *testing.T) {
	stack := newIntegrationStackWithModeAndConfig(t, "closed", func(cfg *config.Config) {
		cfg.LockoutThreshold = 3
		cfg.LockoutDuration = time.Second
	})
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "mfa-lock-user", "MfaLockPassword1")
	accessToken := loginUser(t, stack, user.Username, "MfaLockPassword1")
	status, body := stack.jsonRequest(t, http.MethodPost, "/me/totp/enroll", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("TOTP lockout enroll status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var enrollment totpEnrollResponse
	decodeResponse(t, body, &enrollment)
	code, err := authn.TOTPCode(enrollment.Secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate lockout confirmation code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/confirm", map[string]string{"code": code}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("TOTP lockout confirm status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "MfaLockPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("lockout MFA challenge status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var challenge mfaChallengeResponse
	decodeResponse(t, body, &challenge)
	for attempt := range 3 {
		status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
			"mfa_token": challenge.MFAToken,
			"code":      "000000",
		}, "")
		if status != http.StatusUnauthorized {
			t.Fatalf("wrong MFA code attempt %d status = %d, want %d: %s", attempt+1, status, http.StatusUnauthorized, body)
		}
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      code,
	}, "")
	if status != http.StatusLocked {
		t.Fatalf("locked MFA status = %d, want %d: %s", status, http.StatusLocked, body)
	}
	time.Sleep(1200 * time.Millisecond)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      code,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("MFA login after lockout expiry status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
}

func TestWeakPasswordsAreRejected(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "open")
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "weak-register",
		"email":    "weak-register@example.test",
		"password": "short1",
	}, "")
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("weak registration = %d %s, want weak_password 422", status, body)
	}

	admin := seedPasswordUser(t, context.Background(), stack.database.pool, "weak-admin", "WeakAdminPassword1")
	bootstrapTestAdmin(t, context.Background(), stack.database.pool, admin.ID)
	adminToken := loginUser(t, stack, admin.Username, "WeakAdminPassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{
		"kind":     "password",
		"password": "short1",
	}, adminToken)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("weak admin credential = %d %s, want weak_password 422", status, body)
	}
}
