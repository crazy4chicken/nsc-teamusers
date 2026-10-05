package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/authn"
	"teamusers/internal/config"
	"teamusers/internal/store"
)

type stepUpBeginResponseForTest struct {
	StepUpToken string   `json:"step_up_token"`
	Methods     []string `json:"methods"`
	ExpiresIn   int64    `json:"expires_in"`
	PublicKey   *struct {
		Challenge        string `json:"challenge"`
		UserVerification string `json:"userVerification"`
	} `json:"public_key"`
}

type stepUpAccessClaimsForTest struct {
	AuthTime   int64    `json:"auth_time"`
	StepUpTime int64    `json:"step_up_time"`
	AMR        []string `json:"amr"`
}

type stepUpSessionStateForTest struct {
	FamilyID       string
	FamilyNotAfter time.Time
	Revoked        bool
	AuthTime       int64    `json:"auth_time"`
	StepUpTime     int64    `json:"step_up_time"`
	AMR            []string `json:"amr"`
}

func TestStepUpTOTPRefreshAndFamilyRotation(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-totp", "StepUpTOTPPassword1")
	original := loginUserPair(t, stack, user.Username, "StepUpTOTPPassword1")
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "totp", Hash: secret,
	}); err != nil {
		t.Fatalf("create TOTP credential: %v", err)
	}
	originalClaims := stepUpAccessClaims(t, original.AccessToken)
	if originalClaims.AuthTime <= 0 || originalClaims.StepUpTime != 0 {
		t.Fatalf("primary access evidence = %+v, want positive auth_time and no step_up_time", originalClaims)
	}
	originalSession := readStepUpSessionState(t, stack, original.RefreshToken)
	status, body, challenge := beginStepUpForTest(t, stack, original, original.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	if challenge.StepUpToken == "" || challenge.ExpiresIn != 300 || !containsStringForTest(challenge.Methods, "otp") {
		t.Fatalf("step-up begin response = %+v, want five-minute OTP challenge", challenge)
	}
	code, err := authn.TOTPCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": original.RefreshToken, "step_up_token": challenge.StepUpToken, "code": code,
	}, original.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up completion = %d, want %d: %s", status, http.StatusOK, body)
	}
	var completed tokenPair
	decodeResponse(t, body, &completed)
	assertTokenPair(t, completed)
	completedClaims := stepUpAccessClaims(t, completed.AccessToken)
	if completedClaims.AuthTime != originalClaims.AuthTime || completedClaims.StepUpTime <= 0 ||
		strings.Join(completedClaims.AMR, ",") != strings.Join(originalClaims.AMR, ",") {
		t.Fatalf("completed access evidence = %+v, want unchanged primary evidence and recent step-up time", completedClaims)
	}
	completedSession := readStepUpSessionState(t, stack, completed.RefreshToken)
	if completedSession.FamilyID != originalSession.FamilyID || !completedSession.FamilyNotAfter.Equal(originalSession.FamilyNotAfter) ||
		completedSession.AuthTime != originalSession.AuthTime || completedSession.StepUpTime != completedClaims.StepUpTime ||
		strings.Join(completedSession.AMR, ",") != strings.Join(originalSession.AMR, ",") {
		t.Fatalf("rotated session state = %+v, want preserved family cap and authentication evidence", completedSession)
	}
	if !readStepUpSessionState(t, stack, original.RefreshToken).Revoked {
		t.Fatal("step-up did not revoke the presented refresh session")
	}
	if countStepUpChallenges(t, stack, user.ID) != 0 {
		t.Fatal("successful step-up did not consume its persisted challenge")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": completed.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("post-step-up refresh = %d, want %d: %s", status, http.StatusOK, body)
	}
	var refreshed tokenPair
	decodeResponse(t, body, &refreshed)
	assertTokenPair(t, refreshed)
	refreshedClaims := stepUpAccessClaims(t, refreshed.AccessToken)
	refreshedSession := readStepUpSessionState(t, stack, refreshed.RefreshToken)
	if refreshedClaims.AuthTime != originalClaims.AuthTime || refreshedClaims.StepUpTime != completedClaims.StepUpTime ||
		strings.Join(refreshedClaims.AMR, ",") != strings.Join(originalClaims.AMR, ",") ||
		refreshedSession.FamilyID != originalSession.FamilyID || !refreshedSession.FamilyNotAfter.Equal(originalSession.FamilyNotAfter) ||
		refreshedSession.StepUpTime != completedClaims.StepUpTime {
		t.Fatalf("refreshed step-up evidence = claims %+v, session %+v", refreshedClaims, refreshedSession)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": refreshed.RefreshToken, "step_up_token": challenge.StepUpToken, "code": code,
	}, refreshed.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("replayed step-up challenge = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
}

func TestStepUpBackupCodeFailureLeavesChallengeAndCodeAvailable(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-backup", "StepUpBackupPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpBackupPassword1")
	const backupCode = "abcd-efgh-ijkl-mnop"
	canonical := strings.ReplaceAll(backupCode, "-", "")
	digest := sha256.Sum256([]byte(canonical))
	storedDigests, err := json.Marshal([]string{hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatalf("encode backup-code digest: %v", err)
	}
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "backup_codes", Hash: string(storedDigests),
	}); err != nil {
		t.Fatalf("create backup-code credential: %v", err)
	}
	var remainingDigests []string
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	if len(challenge.Methods) != 1 || challenge.Methods[0] != "backup_code" {
		t.Fatalf("step-up methods = %v, want only backup_code", challenge.Methods)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "code": "invalid-backup-code",
	}, primary.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("invalid backup-code proof = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if countStepUpChallenges(t, stack, user.ID) != 1 || readStepUpSessionState(t, stack, primary.RefreshToken).Revoked {
		t.Fatal("failed proof consumed the challenge or changed the refresh session")
	}
	var storedHash string
	if err := stack.database.pool.QueryRow(ctx, `SELECT hash FROM credentials WHERE user_id = $1 AND kind = 'backup_codes'`, user.ID).Scan(&storedHash); err != nil {
		t.Fatalf("read backup codes after failed proof: %v", err)
	}
	if err := json.Unmarshal([]byte(storedHash), &remainingDigests); err != nil || len(remainingDigests) != 1 {
		t.Fatalf("backup codes after failed proof = %v, %v; want one unused code", remainingDigests, err)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "code": backupCode,
	}, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("valid backup-code proof = %d, want %d: %s", status, http.StatusOK, body)
	}
	var completed tokenPair
	decodeResponse(t, body, &completed)
	assertTokenPair(t, completed)
	var remainingCredentials int
	if err := stack.database.pool.QueryRow(ctx, `SELECT count(*) FROM credentials WHERE user_id = $1 AND kind = 'backup_codes'`, user.ID).Scan(&remainingCredentials); err != nil {
		t.Fatalf("count backup-code credentials after completion: %v", err)
	}
	if remainingCredentials != 0 || countStepUpChallenges(t, stack, user.ID) != 0 {
		t.Fatal("successful backup-code proof did not atomically consume the code and challenge")
	}
}

func TestStepUpFailedProofUsesAccountLockout(t *testing.T) {
	stack := newIntegrationStackWithModeAndConfig(t, "closed", func(cfg *config.Config) {
		cfg.LockoutThreshold = 1
		cfg.LockoutDuration = time.Hour
	})
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-lockout", "StepUpLockoutPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpLockoutPassword1")
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "totp", Hash: secret,
	}); err != nil {
		t.Fatalf("create TOTP credential: %v", err)
	}
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	request := map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "code": "invalid",
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", request, primary.AccessToken)
	if status != http.StatusLocked || !strings.Contains(string(body), "account_locked") {
		t.Fatalf("failed step-up proof = %d %s, want account_locked 423", status, body)
	}
	if countStepUpChallenges(t, stack, user.ID) != 1 || readStepUpSessionState(t, stack, primary.RefreshToken).Revoked {
		t.Fatal("lockout failure consumed the challenge or changed the refresh session")
	}
	code, err := authn.TOTPCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	request["code"] = code
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", request, primary.AccessToken)
	if status != http.StatusLocked || !strings.Contains(string(body), "account_locked") {
		t.Fatalf("locked-account step-up retry = %d %s, want account_locked 423", status, body)
	}
	var failedLogins int
	if err := stack.database.pool.QueryRow(ctx, `SELECT failed_logins FROM users WHERE id = $1`, user.ID).Scan(&failedLogins); err != nil {
		t.Fatalf("read failed login count: %v", err)
	}
	if failedLogins != 1 {
		t.Fatalf("failed login count = %d, want 1", failedLogins)
	}
}

func TestStepUpPasskeyRequiresUserVerification(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-passkey", "StepUpPasskeyPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpPasskeyPassword1")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}
	registerSoftPasskey(t, stack, primary.AccessToken, privateKey, credentialID)
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	if challenge.PublicKey == nil || challenge.PublicKey.Challenge == "" || challenge.PublicKey.UserVerification != "required" ||
		len(challenge.Methods) != 1 || challenge.Methods[0] != "webauthn" {
		t.Fatalf("step-up passkey options = %+v, want userVerification required", challenge)
	}

	credential := signedStepUpAssertion(t, challenge.PublicKey.Challenge, user.ID, credentialID, privateKey, false)
	request := map[string]any{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "credential": credential,
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", request, primary.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("non-UV passkey proof = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if countStepUpChallenges(t, stack, user.ID) != 1 || readStepUpSessionState(t, stack, primary.RefreshToken).Revoked {
		t.Fatal("non-UV proof consumed the challenge or changed the refresh session")
	}

	request["credential"] = signedStepUpAssertion(t, challenge.PublicKey.Challenge, user.ID, credentialID, privateKey, true)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", request, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("UV passkey proof = %d, want %d: %s", status, http.StatusOK, body)
	}
	var completed tokenPair
	decodeResponse(t, body, &completed)
	assertTokenPair(t, completed)
	if stepUpAccessClaims(t, completed.AccessToken).StepUpTime <= 0 || countStepUpChallenges(t, stack, user.ID) != 0 {
		t.Fatal("valid UV passkey proof did not issue step-up evidence and consume its challenge")
	}
}

func TestStepUpWithoutFactorsFallsBackToFullAuthentication(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "step-up-no-factor", "StepUpNoFactorPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpNoFactorPassword1")
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/step-up/begin", map[string]string{}, primary.AccessToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "refresh_token is required") {
		t.Fatalf("step-up begin without refresh token = %d %s, want refresh_token required 400", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": "unused",
	}, primary.AccessToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "exactly one of code or credential is required") {
		t.Fatalf("step-up complete without proof = %d %s, want exactly-one-proof 400", status, body)
	}
	status, body, _ = beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusForbidden || !strings.Contains(string(body), "step_up_not_available") {
		t.Fatalf("step-up without factors = %d %s, want step_up_not_available 403", status, body)
	}
	if countStepUpChallenges(t, stack, user.ID) != 0 {
		t.Fatal("no-factor step-up created a challenge")
	}
	if pair := loginUserPair(t, stack, user.Username, "StepUpNoFactorPassword1"); pair.AccessToken == "" {
		t.Fatal("full primary authentication did not remain available")
	}
}

func TestStepUpRejectsServiceAndImpersonationPrincipals(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	ctx := context.Background()
	serviceUser := seedPasswordUser(t, ctx, stack.database.pool, "step-up-service", "StepUpServicePassword1")
	status, body := stack.jsonRequest(t, http.MethodPost, "/users/"+serviceUser.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create service credential = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var serviceCredential credentialResponse
	decodeResponse(t, body, &serviceCredential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id": serviceCredential.ClientID, "client_secret": serviceCredential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("service login = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	assertTokenPair(t, servicePair)

	target := seedPasswordUser(t, ctx, stack.database.pool, "step-up-impersonated", "StepUpImpersonatedPassword1")
	targetPair := loginUserPair(t, stack, target.Username, "StepUpImpersonatedPassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/impersonations", map[string]string{
		"user_id": target.ID, "reason": "step-up eligibility test",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("create impersonation token = %d, want %d: %s", status, http.StatusOK, body)
	}
	var impersonation struct {
		AccessToken string `json:"access_token"`
	}
	decodeResponse(t, body, &impersonation)
	if impersonation.AccessToken == "" {
		t.Fatal("impersonation response has no access token")
	}

	for _, testCase := range []struct {
		name        string
		accessToken string
		refresh     string
	}{
		{name: "service", accessToken: servicePair.AccessToken, refresh: servicePair.RefreshToken},
		{name: "impersonation", accessToken: impersonation.AccessToken, refresh: targetPair.RefreshToken},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			for _, route := range []string{"/auth/step-up/begin", "/auth/step-up/complete"} {
				request := map[string]string{"refresh_token": testCase.refresh, "step_up_token": "unused", "code": "000000"}
				if route == "/auth/step-up/begin" {
					request = map[string]string{"refresh_token": testCase.refresh}
				}
				status, body := stack.jsonRequest(t, http.MethodPost, route, request, testCase.accessToken)
				if status != http.StatusForbidden || !strings.Contains(string(body), "step_up_forbidden") {
					t.Fatalf("%s %s = %d %s, want step_up_forbidden 403", testCase.name, route, status, body)
				}
			}
		})
	}
	if countStepUpChallenges(t, stack, admin.ID) != 0 || countStepUpChallenges(t, stack, serviceUser.ID) != 0 || countStepUpChallenges(t, stack, target.ID) != 0 {
		t.Fatal("ineligible principals created a step-up challenge")
	}
}

func TestStepUpRejectsRefreshSessionMismatchWithoutConsumingChallenge(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-session-binding", "StepUpSessionPassword1")
	first := loginUserPair(t, stack, user.Username, "StepUpSessionPassword1")
	second := loginUserPair(t, stack, user.Username, "StepUpSessionPassword1")
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "totp", Hash: secret,
	}); err != nil {
		t.Fatalf("create TOTP credential: %v", err)
	}
	status, body, challenge := beginStepUpForTest(t, stack, first, first.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	code, err := authn.TOTPCode(secret, time.Now().UTC())
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	request := map[string]string{"refresh_token": second.RefreshToken, "step_up_token": challenge.StepUpToken, "code": code}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", request, first.AccessToken)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong-session step-up completion = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if countStepUpChallenges(t, stack, user.ID) != 1 || readStepUpSessionState(t, stack, first.RefreshToken).Revoked ||
		readStepUpSessionState(t, stack, second.RefreshToken).Revoked {
		t.Fatal("wrong-session proof consumed the challenge or changed either refresh session")
	}
	request["refresh_token"] = first.RefreshToken
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/step-up/complete", request, first.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("matching-session step-up completion = %d, want %d: %s", status, http.StatusOK, body)
	}
}

func beginStepUpForTest(t *testing.T, stack *integrationStack, pair tokenPair, accessToken string) (int, []byte, stepUpBeginResponseForTest) {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/step-up/begin", map[string]string{
		"refresh_token": pair.RefreshToken,
	}, accessToken)
	var response stepUpBeginResponseForTest
	if status == http.StatusOK {
		decodeResponse(t, body, &response)
	}
	return status, body, response
}

func stepUpAccessClaims(t *testing.T, accessToken string) stepUpAccessClaimsForTest {
	t.Helper()
	var claims stepUpAccessClaimsForTest
	decodeTokenClaims(t, accessToken, &claims)
	return claims
}

func readStepUpSessionState(t *testing.T, stack *integrationStack, refreshToken string) stepUpSessionStateForTest {
	t.Helper()
	var state stepUpSessionStateForTest
	var clientMeta []byte
	err := stack.database.pool.QueryRow(context.Background(), `
		SELECT family_id, family_not_after, revoked_at IS NOT NULL, client_meta
		FROM sessions WHERE id = $1`, refreshSessionID(refreshToken)).Scan(
		&state.FamilyID, &state.FamilyNotAfter, &state.Revoked, &clientMeta,
	)
	if err != nil {
		t.Fatalf("read refresh session state: %v", err)
	}
	var metadata struct {
		AuthTime   int64    `json:"auth_time"`
		StepUpTime int64    `json:"step_up_time"`
		AMR        []string `json:"amr"`
	}
	if err := json.Unmarshal(clientMeta, &metadata); err != nil {
		t.Fatalf("decode refresh session metadata: %v", err)
	}
	state.AuthTime = metadata.AuthTime
	state.StepUpTime = metadata.StepUpTime
	state.AMR = metadata.AMR
	return state
}

func countStepUpChallenges(t *testing.T, stack *integrationStack, userID string) int {
	t.Helper()
	var count int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM step_up_challenges WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("count step-up challenges: %v", err)
	}
	return count
}

func containsStringForTest(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func signedStepUpAssertion(t *testing.T, challenge, userID string, credentialID []byte, privateKey *ecdsa.PrivateKey, userVerified bool) map[string]any {
	return signedAssertionForTest(t, challenge, userID, credentialID, privateKey, 1, userVerified)
}

func signedAssertionForTest(t *testing.T, challenge, userID string, credentialID []byte, privateKey *ecdsa.PrivateKey, counter uint32, userVerified bool) map[string]any {
	t.Helper()
	clientData := clientDataJSON("webauthn.get", challenge, "http://localhost")
	authenticatorData := assertionAuthenticatorData("localhost", counter, userVerified)
	clientDataHash := sha256.Sum256(clientData)
	signedData := append(append([]byte(nil), authenticatorData...), clientDataHash[:]...)
	assertionHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, assertionHash[:])
	if err != nil {
		t.Fatalf("sign passkey assertion: %v", err)
	}
	credentialIDText := base64.RawURLEncoding.EncodeToString(credentialID)
	return map[string]any{
		"id": credentialIDText, "rawId": credentialIDText, "type": "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(clientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(authenticatorData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString([]byte(userID)),
		},
	}
}

type stepUpTestClock struct {
	mu  sync.RWMutex
	now time.Time
}

func newStepUpTestClock() *stepUpTestClock {
	return &stepUpTestClock{now: time.Now().UTC().Truncate(time.Second)}
}

func (clock *stepUpTestClock) Now() time.Time {
	clock.mu.RLock()
	defer clock.mu.RUnlock()
	return clock.now
}

func (clock *stepUpTestClock) Set(now time.Time) {
	clock.mu.Lock()
	clock.now = now.UTC()
	clock.mu.Unlock()
}

type stepUpTestRequestResult struct {
	name   string
	status int
	body   []byte
	err    error
}

func sendStepUpTestRequest(ctx context.Context, stack *integrationStack, method, path string, body any, bearer string) (int, []byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, method, stack.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	response, err := stack.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, responseBody, nil
}

func launchStepUpTestRequest(ctx context.Context, stack *integrationStack, results chan<- stepUpTestRequestResult, name, method, path string, body any, bearer string) {
	go func() {
		status, responseBody, err := sendStepUpTestRequest(ctx, stack, method, path, body, bearer)
		results <- stepUpTestRequestResult{name: name, status: status, body: responseBody, err: err}
	}()
}

func awaitStepUpTestRequest(t *testing.T, ctx context.Context, results <-chan stepUpTestRequestResult) stepUpTestRequestResult {
	t.Helper()
	select {
	case result := <-results:
		if result.err != nil {
			t.Fatalf("%s request: %v", result.name, result.err)
		}
		return result
	case <-ctx.Done():
		t.Fatalf("waiting for request result: %v", ctx.Err())
		return stepUpTestRequestResult{}
	}
}

func holdStepUpTestLock(t *testing.T, stack *integrationStack, acquire func(context.Context, pgx.Tx) error) func() {
	t.Helper()
	ctx := context.Background()
	conn, err := stack.database.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire lock connection: %v", err)
		return func() {}
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Release()
		t.Fatalf("begin lock transaction: %v", err)
		return func() {}
	}
	if err := acquire(ctx, tx); err != nil {
		_ = tx.Rollback(ctx)
		conn.Release()
		t.Fatalf("acquire test lock: %v", err)
		return func() {}
	}
	var once sync.Once
	release := func() {
		once.Do(func() {
			_ = tx.Rollback(context.Background())
			conn.Release()
		})
	}
	t.Cleanup(release)
	return release
}

func waitForStepUpTestLockWait(t *testing.T, stack *integrationStack, queryFragment string, count int) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	ticker := time.NewTicker(10 * time.Millisecond)
	defer ticker.Stop()
	for {
		var waiting int
		err := stack.database.pool.QueryRow(ctx, `
			SELECT count(*) FROM pg_stat_activity
			WHERE datname = current_database()
			  AND state = 'active'
			  AND wait_event_type = 'Lock'
			  AND query ILIKE '%' || $1 || '%'`, queryFragment).Scan(&waiting)
		if err != nil {
			t.Fatalf("inspect PostgreSQL lock waits: %v", err)
			return
		}
		if waiting >= count {
			return
		}
		select {
		case <-ctx.Done():
			t.Fatalf("timed out waiting for %d PostgreSQL lock wait(s) on %q", count, queryFragment)
			return
		case <-ticker.C:
		}
	}
}

func assertStepUpTestCredentialLockAvailable(t *testing.T, stack *integrationStack, userID, kind string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	conn, err := stack.database.pool.Acquire(ctx)
	if err != nil {
		t.Fatalf("acquire credential probe connection: %v", err)
		return
	}
	tx, err := conn.Begin(ctx)
	if err != nil {
		conn.Release()
		t.Fatalf("begin credential probe transaction: %v", err)
		return
	}
	var lockedUserID string
	if err := tx.QueryRow(ctx, `SELECT user_id FROM credentials WHERE user_id = $1 AND kind = $2 FOR UPDATE`, userID, kind).Scan(&lockedUserID); err != nil {
		_ = tx.Rollback(context.Background())
		conn.Release()
		t.Fatalf("credential row %q was locked before the user row: %v", kind, err)
		return
	}
	if err := tx.Rollback(ctx); err != nil {
		conn.Release()
		t.Fatalf("release credential probe transaction: %v", err)
		return
	}
	conn.Release()
}

func addStepUpTestBackupCode(t *testing.T, stack *integrationStack, userID, backupCode string) {
	t.Helper()
	canonical := strings.ToLower(strings.ReplaceAll(backupCode, "-", ""))
	digest := sha256.Sum256([]byte(canonical))
	encoded, err := json.Marshal([]string{hex.EncodeToString(digest[:])})
	if err != nil {
		t.Fatalf("encode backup-code digest: %v", err)
	}
	if _, err := store.CreateCredential(context.Background(), stack.database.pool, store.Credential{
		UserID: userID, Kind: "backup_codes", Hash: string(encoded),
	}); err != nil {
		t.Fatalf("create backup-code credential: %v", err)
	}
}

func stepUpTestCredentialHash(t *testing.T, stack *integrationStack, userID, kind string) string {
	t.Helper()
	var hash string
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT hash FROM credentials WHERE user_id = $1 AND kind = $2`, userID, kind).Scan(&hash); err != nil {
		t.Fatalf("read %q credential: %v", kind, err)
	}
	return hash
}

func countStepUpTestSessions(t *testing.T, stack *integrationStack, userID string) int {
	t.Helper()
	var count int
	if err := stack.database.pool.QueryRow(context.Background(), `SELECT count(*) FROM sessions WHERE user_id = $1`, userID).Scan(&count); err != nil {
		t.Fatalf("count user sessions: %v", err)
	}
	return count
}

func countStepUpSuccessAudits(t *testing.T, stack *integrationStack, userID string) int {
	t.Helper()
	var count int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE actor_id = $1 AND action = 'auth.step_up.succeeded'`, userID).Scan(&count); err != nil {
		t.Fatalf("count step-up success audits: %v", err)
	}
	return count
}

func setStepUpWebAuthnSessionExpiry(t *testing.T, stack *integrationStack, userID string, expires time.Time) {
	t.Helper()
	var challengeID string
	var rawSession []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT id, webauthn_session FROM step_up_challenges WHERE user_id = $1`, userID).Scan(&challengeID, &rawSession); err != nil {
		t.Fatalf("read step-up WebAuthn session: %v", err)
	}
	var session webauthnlib.SessionData
	if err := json.Unmarshal(rawSession, &session); err != nil {
		t.Fatalf("decode step-up WebAuthn session: %v", err)
	}
	session.Expires = expires
	encoded, err := json.Marshal(session)
	if err != nil {
		t.Fatalf("encode step-up WebAuthn session: %v", err)
	}
	if _, err := stack.database.pool.Exec(context.Background(), `
		UPDATE step_up_challenges SET webauthn_session = $2 WHERE id = $1`, challengeID, encoded); err != nil {
		t.Fatalf("set step-up WebAuthn session expiry: %v", err)
	}
}

func TestStepUpBeginRevalidatesSessionAfterUserLock(t *testing.T) {
	clock := newStepUpTestClock()
	stack := newIntegrationStackWithModeAndConfigAndNow(t, "closed", nil, clock.Now)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-user-lock-expiry", "StepUpUserLockPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpUserLockPassword1")
	addStepUpTestTOTPCredential(t, stack, user.ID, "JBSWY3DPEHPK3PXP")
	initial := clock.Now()
	expiresAt := initial.Add(time.Minute)
	if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET expires_at = $2 WHERE id = $1`, refreshSessionID(primary.RefreshToken), expiresAt); err != nil {
		t.Fatalf("expire test refresh session: %v", err)
	}
	userLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedUserID string
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, user.ID).Scan(&lockedUserID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 1)
	launchStepUpTestRequest(requestCtx, stack, results, "step-up begin", http.MethodPost, "/auth/step-up/begin", map[string]string{
		"refresh_token": primary.RefreshToken,
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 1)
	clock.Set(expiresAt.Add(time.Second))
	userLock()
	result := awaitStepUpTestRequest(t, requestCtx, results)
	if result.status != http.StatusUnauthorized {
		t.Fatalf("step-up begin after session expiry = %d, want %d: %s", result.status, http.StatusUnauthorized, result.body)
	}
	state := readStepUpSessionState(t, stack, primary.RefreshToken)
	if state.Revoked || state.StepUpTime != 0 || countStepUpChallenges(t, stack, user.ID) != 0 {
		t.Fatalf("expired-session begin changed step-up state: session %+v, challenges %d", state, countStepUpChallenges(t, stack, user.ID))
	}
}

func TestStepUpRejectsTOTPExpiredDuringCredentialLockWait(t *testing.T) {
	clock := newStepUpTestClock()
	stack := newIntegrationStackWithModeAndConfigAndNow(t, "closed", nil, clock.Now)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-totp-lock-expiry", "StepUpTOTPLockPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpTOTPLockPassword1")
	const secret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	addStepUpTestTOTPCredential(t, stack, user.ID, secret)
	initial := clock.Now()
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	code, err := authn.TOTPCode(secret, initial)
	if err != nil {
		t.Fatalf("generate delayed-lock TOTP code: %v", err)
	}
	credentialLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedUserID string
		return tx.QueryRow(ctx, `SELECT user_id FROM credentials WHERE user_id = $1 AND kind = 'totp' FOR UPDATE`, user.ID).Scan(&lockedUserID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 1)
	launchStepUpTestRequest(requestCtx, stack, results, "TOTP step-up", http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "code": code,
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "FROM credentials WHERE user_id", 1)
	clock.Set(initial.Add(2 * time.Minute))
	credentialLock()
	result := awaitStepUpTestRequest(t, requestCtx, results)
	if result.status != http.StatusUnauthorized {
		t.Fatalf("expired TOTP proof = %d, want %d: %s", result.status, http.StatusUnauthorized, result.body)
	}
	state := readStepUpSessionState(t, stack, primary.RefreshToken)
	if state.Revoked || state.StepUpTime != 0 || countStepUpChallenges(t, stack, user.ID) != 1 {
		t.Fatalf("expired TOTP changed step-up state: session %+v, challenges %d", state, countStepUpChallenges(t, stack, user.ID))
	}
}

func TestStepUpRejectsExpiredWebAuthnSessionAfterCredentialLockWait(t *testing.T) {
	clock := newStepUpTestClock()
	stack := newIntegrationStackWithModeAndConfigAndNow(t, "closed", nil, clock.Now)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-webauthn-lock-expiry", "StepUpWebAuthnLockPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpWebAuthnLockPassword1")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}
	registerSoftPasskey(t, stack, primary.AccessToken, privateKey, credentialID)
	initial := clock.Now()
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK || challenge.PublicKey == nil {
		t.Fatalf("passkey step-up begin = %d, want %d with WebAuthn options: %s", status, http.StatusOK, body)
	}
	passkeyHash := stepUpTestCredentialHash(t, stack, user.ID, store.PasskeyCredentialKind)
	expiresAt := initial.Add(time.Minute)
	setStepUpWebAuthnSessionExpiry(t, stack, user.ID, expiresAt)
	credentialLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedUserID string
		return tx.QueryRow(ctx, `SELECT user_id FROM credentials WHERE user_id = $1 AND kind = $2 FOR UPDATE`, user.ID, store.PasskeyCredentialKind).Scan(&lockedUserID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 1)
	launchStepUpTestRequest(requestCtx, stack, results, "WebAuthn step-up", http.MethodPost, "/auth/step-up/complete", map[string]any{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken,
		"credential": signedStepUpAssertion(t, challenge.PublicKey.Challenge, user.ID, credentialID, privateKey, true),
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "SELECT hash FROM credentials", 1)
	clock.Set(expiresAt.Add(time.Second))
	credentialLock()
	result := awaitStepUpTestRequest(t, requestCtx, results)
	if result.status != http.StatusUnauthorized {
		t.Fatalf("expired WebAuthn step-up proof = %d, want %d: %s", result.status, http.StatusUnauthorized, result.body)
	}
	state := readStepUpSessionState(t, stack, primary.RefreshToken)
	if state.Revoked || state.StepUpTime != 0 || countStepUpChallenges(t, stack, user.ID) != 1 {
		t.Fatalf("expired WebAuthn proof changed step-up state: session %+v, challenges %d", state, countStepUpChallenges(t, stack, user.ID))
	}
	if got := stepUpTestCredentialHash(t, stack, user.ID, store.PasskeyCredentialKind); got != passkeyHash {
		t.Fatal("expired WebAuthn proof changed the passkey credential")
	}
}

func TestStepUpFinalExpiryRollsBackBackupProofAndSession(t *testing.T) {
	clock := newStepUpTestClock()
	stack := newIntegrationStackWithModeAndConfigAndNow(t, "closed", nil, clock.Now)
	cases := []struct {
		name    string
		advance time.Duration
	}{
		{name: "refresh-session-expiry", advance: time.Minute + time.Second},
		{name: "family-cap", advance: time.Minute + time.Second},
		{name: "idle-timeout", advance: 2 * time.Second},
		{name: "challenge-expiry", advance: 5*time.Minute + time.Second},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			initial := time.Now().UTC().Truncate(time.Second)
			clock.Set(initial)
			ctx := context.Background()
			user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-final-"+testCase.name, "StepUpFinalExpiryPassword1")
			primary := loginUserPair(t, stack, user.Username, "StepUpFinalExpiryPassword1")
			const backupCode = "abcd-efgh-ijkl-mnop"
			addStepUpTestBackupCode(t, stack, user.ID, backupCode)
			sessionID := refreshSessionID(primary.RefreshToken)
			switch testCase.name {
			case "refresh-session-expiry":
				if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET expires_at = $2 WHERE id = $1`, sessionID, initial.Add(time.Minute)); err != nil {
					t.Fatalf("set original session expiry: %v", err)
				}
			case "family-cap":
				if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET family_not_after = $2 WHERE id = $1`, sessionID, initial.Add(time.Minute)); err != nil {
					t.Fatalf("set refresh-family cap: %v", err)
				}
			case "idle-timeout":
				idleTimeout := 1
				insertSessionTestPolicy(t, ctx, stack, "step-up-final-idle-timeout", "default", "", 100, nil, &idleTimeout)
				if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET last_active_at = $2 WHERE id = $1`, sessionID, initial.Add(-59*time.Second)); err != nil {
					t.Fatalf("set original session activity time: %v", err)
				}
			}
			status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
			if status != http.StatusOK || !containsStringForTest(challenge.Methods, "backup_code") {
				t.Fatalf("backup-code step-up begin = %d, want %d: %s", status, http.StatusOK, body)
			}
			backupHash := stepUpTestCredentialHash(t, stack, user.ID, "backup_codes")
			sessionCount := countStepUpTestSessions(t, stack, user.ID)
			auditCount := countStepUpSuccessAudits(t, stack, user.ID)
			auditLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
				_, err := tx.Exec(ctx, `LOCK TABLE audit_log IN ACCESS EXCLUSIVE MODE`)
				return err
			})
			requestCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
			defer cancel()
			results := make(chan stepUpTestRequestResult, 1)
			launchStepUpTestRequest(requestCtx, stack, results, "backup-code step-up", http.MethodPost, "/auth/step-up/complete", map[string]string{
				"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "code": backupCode,
			}, primary.AccessToken)
			waitForStepUpTestLockWait(t, stack, "INSERT INTO audit_log", 1)
			advance := testCase.advance
			if testCase.name == "challenge-expiry" {
				advance = time.Duration(challenge.ExpiresIn)*time.Second + time.Second
			}
			clock.Set(initial.Add(advance))
			auditLock()
			result := awaitStepUpTestRequest(t, requestCtx, results)
			cancel()
			if result.status != http.StatusUnauthorized {
				t.Fatalf("step-up completion after %s = %d, want %d: %s", testCase.name, result.status, http.StatusUnauthorized, result.body)
			}
			state := readStepUpSessionState(t, stack, primary.RefreshToken)
			if state.Revoked || state.StepUpTime != 0 || countStepUpChallenges(t, stack, user.ID) != 1 {
				t.Fatalf("final expiry changed challenge/session state: session %+v, challenges %d", state, countStepUpChallenges(t, stack, user.ID))
			}
			if got := stepUpTestCredentialHash(t, stack, user.ID, "backup_codes"); got != backupHash {
				t.Fatal("final expiry did not roll back backup-code consumption")
			}
			if got := countStepUpTestSessions(t, stack, user.ID); got != sessionCount {
				t.Fatalf("session count after final expiry = %d, want %d", got, sessionCount)
			}
			if got := countStepUpSuccessAudits(t, stack, user.ID); got != auditCount {
				t.Fatalf("successful step-up audit count after final expiry = %d, want %d", got, auditCount)
			}
		})
	}
}

func TestStepUpFinalWebAuthnExpiryRollsBackPasskeyAndSession(t *testing.T) {
	clock := newStepUpTestClock()
	stack := newIntegrationStackWithModeAndConfigAndNow(t, "closed", nil, clock.Now)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-webauthn-final-expiry", "StepUpWebAuthnFinalPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpWebAuthnFinalPassword1")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}
	registerSoftPasskey(t, stack, primary.AccessToken, privateKey, credentialID)
	initial := clock.Now()
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK || challenge.PublicKey == nil {
		t.Fatalf("passkey step-up begin = %d, want %d with WebAuthn options: %s", status, http.StatusOK, body)
	}
	passkeyHash := stepUpTestCredentialHash(t, stack, user.ID, store.PasskeyCredentialKind)
	sessionExpiresAt := initial.Add(time.Minute)
	setStepUpWebAuthnSessionExpiry(t, stack, user.ID, sessionExpiresAt)
	sessionCount := countStepUpTestSessions(t, stack, user.ID)
	auditCount := countStepUpSuccessAudits(t, stack, user.ID)
	auditLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		_, err := tx.Exec(ctx, `LOCK TABLE audit_log IN ACCESS EXCLUSIVE MODE`)
		return err
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 1)
	launchStepUpTestRequest(requestCtx, stack, results, "WebAuthn step-up", http.MethodPost, "/auth/step-up/complete", map[string]any{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken,
		"credential": signedStepUpAssertion(t, challenge.PublicKey.Challenge, user.ID, credentialID, privateKey, true),
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "INSERT INTO audit_log", 1)
	clock.Set(sessionExpiresAt.Add(time.Second))
	auditLock()
	result := awaitStepUpTestRequest(t, requestCtx, results)
	if result.status != http.StatusUnauthorized {
		t.Fatalf("completion after WebAuthn session expiry = %d, want %d: %s", result.status, http.StatusUnauthorized, result.body)
	}
	state := readStepUpSessionState(t, stack, primary.RefreshToken)
	if state.Revoked || state.StepUpTime != 0 || countStepUpChallenges(t, stack, user.ID) != 1 {
		t.Fatalf("final WebAuthn expiry changed step-up state: session %+v, challenges %d", state, countStepUpChallenges(t, stack, user.ID))
	}
	if got := stepUpTestCredentialHash(t, stack, user.ID, store.PasskeyCredentialKind); got != passkeyHash {
		t.Fatal("final WebAuthn expiry did not roll back the passkey counter update")
	}
	if got := countStepUpTestSessions(t, stack, user.ID); got != sessionCount {
		t.Fatalf("session count after WebAuthn expiry = %d, want %d", got, sessionCount)
	}
	if got := countStepUpSuccessAudits(t, stack, user.ID); got != auditCount {
		t.Fatalf("successful step-up audit count after WebAuthn expiry = %d, want %d", got, auditCount)
	}
}

func TestConcurrentStepUpAndBackupLoginLockUserBeforeCredentials(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-backup-lock-order", "StepUpBackupLockPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpBackupLockPassword1")
	addStepUpTestTOTPCredential(t, stack, user.ID, "JBSWY3DPEHPK3PXP")
	const backupCode = "abcd-efgh-ijkl-mnop"
	addStepUpTestBackupCode(t, stack, user.ID, backupCode)
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username, "password": "StepUpBackupLockPassword1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("MFA login begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	var mfaChallenge mfaChallengeResponse
	decodeResponse(t, body, &mfaChallenge)
	if !mfaChallenge.MFARequired || mfaChallenge.MFAToken == "" {
		t.Fatalf("MFA login challenge = %+v, want an MFA token", mfaChallenge)
	}
	status, body, stepUpChallenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	userLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedUserID string
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, user.ID).Scan(&lockedUserID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 2)
	launchStepUpTestRequest(requestCtx, stack, results, "step-up", http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": stepUpChallenge.StepUpToken, "code": backupCode,
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 1)
	launchStepUpTestRequest(requestCtx, stack, results, "backup login", http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": mfaChallenge.MFAToken, "code": backupCode,
	}, "")
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 2)
	assertStepUpTestCredentialLockAvailable(t, stack, user.ID, "backup_codes")
	userLock()
	first := awaitStepUpTestRequest(t, requestCtx, results)
	second := awaitStepUpTestRequest(t, requestCtx, results)
	successes := 0
	for _, result := range []stepUpTestRequestResult{first, second} {
		if result.status == http.StatusOK {
			successes++
		} else if result.status != http.StatusUnauthorized {
			t.Fatalf("%s result = %d, want %d or %d: %s", result.name, result.status, http.StatusOK, http.StatusUnauthorized, result.body)
		}
	}
	if successes != 1 {
		t.Fatalf("backup-code consumers succeeded %d times, want exactly once", successes)
	}
}

func TestConcurrentStepUpAndPasskeyLoginLockUserBeforeCredentials(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-passkey-lock-order", "StepUpPasskeyLockPassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpPasskeyLockPassword1")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}
	registerSoftPasskey(t, stack, primary.AccessToken, privateKey, credentialID)
	status, body, stepUpChallenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK || stepUpChallenge.PublicKey == nil {
		t.Fatalf("passkey step-up begin = %d, want %d with WebAuthn options: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", map[string]string{
		"username": user.Username,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("passkey login begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	var loginOptions struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &loginOptions)
	if loginOptions.PublicKey.Challenge == "" {
		t.Fatal("passkey login begin returned no challenge")
	}
	stepUpAssertion := signedStepUpAssertion(t, stepUpChallenge.PublicKey.Challenge, user.ID, credentialID, privateKey, true)
	loginAssertion := signedAssertionForTest(t, loginOptions.PublicKey.Challenge, user.ID, credentialID, privateKey, 2, true)
	userLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedUserID string
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, user.ID).Scan(&lockedUserID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 2)
	launchStepUpTestRequest(requestCtx, stack, results, "passkey step-up", http.MethodPost, "/auth/step-up/complete", map[string]any{
		"refresh_token": primary.RefreshToken, "step_up_token": stepUpChallenge.StepUpToken, "credential": stepUpAssertion,
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 1)
	launchStepUpTestRequest(requestCtx, stack, results, "passkey login", http.MethodPost, "/auth/passkey/login/finish", loginAssertion, "")
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 2)
	assertStepUpTestCredentialLockAvailable(t, stack, user.ID, store.PasskeyCredentialKind)
	userLock()
	first := awaitStepUpTestRequest(t, requestCtx, results)
	second := awaitStepUpTestRequest(t, requestCtx, results)
	stepUpSucceeded := false
	for _, result := range []stepUpTestRequestResult{first, second} {
		if result.status != http.StatusOK {
			t.Fatalf("%s result = %d, want %d: %s", result.name, result.status, http.StatusOK, result.body)
		}
		switch result.name {
		case "passkey step-up":
			stepUpSucceeded = true
			var completed tokenPair
			decodeResponse(t, result.body, &completed)
			assertTokenPair(t, completed)
			if stepUpAccessClaims(t, completed.AccessToken).StepUpTime <= 0 || countStepUpChallenges(t, stack, user.ID) != 0 {
				t.Fatal("valid concurrent UV passkey proof did not issue step-up evidence and consume its challenge")
			}
			if !readStepUpSessionState(t, stack, primary.RefreshToken).Revoked {
				t.Fatal("valid concurrent UV passkey proof did not revoke the prior refresh session")
			}
		case "passkey login":
		default:
			t.Fatalf("unexpected concurrent passkey request %q", result.name)
		}
	}
	if !stepUpSucceeded {
		t.Fatal("passkey step-up did not succeed")
	}
}

func TestConcurrentStepUpAndTOTPDisableLockUserBeforeCredentials(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "step-up-totp-delete-lock-order", "StepUpTOTPDeletePassword1")
	primary := loginUserPair(t, stack, user.Username, "StepUpTOTPDeletePassword1")
	addStepUpTestTOTPCredential(t, stack, user.ID, "JBSWY3DPEHPK3PXP")
	const backupCode = "abcd-efgh-ijkl-mnop"
	addStepUpTestBackupCode(t, stack, user.ID, backupCode)
	status, body, challenge := beginStepUpForTest(t, stack, primary, primary.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("step-up begin = %d, want %d: %s", status, http.StatusOK, body)
	}
	userLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedUserID string
		return tx.QueryRow(ctx, `SELECT id FROM users WHERE id = $1 FOR UPDATE`, user.ID).Scan(&lockedUserID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 2)
	launchStepUpTestRequest(requestCtx, stack, results, "step-up", http.MethodPost, "/auth/step-up/complete", map[string]string{
		"refresh_token": primary.RefreshToken, "step_up_token": challenge.StepUpToken, "code": backupCode,
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 1)
	launchStepUpTestRequest(requestCtx, stack, results, "TOTP disable", http.MethodDelete, "/me/totp", map[string]string{
		"code": backupCode,
	}, primary.AccessToken)
	waitForStepUpTestLockWait(t, stack, "SELECT id FROM users", 2)
	assertStepUpTestCredentialLockAvailable(t, stack, user.ID, "backup_codes")
	assertStepUpTestCredentialLockAvailable(t, stack, user.ID, "totp")
	userLock()
	first := awaitStepUpTestRequest(t, requestCtx, results)
	second := awaitStepUpTestRequest(t, requestCtx, results)
	stepUpSuccesses := 0
	deleteSuccesses := 0
	for _, result := range []stepUpTestRequestResult{first, second} {
		switch {
		case result.name == "step-up" && result.status == http.StatusOK:
			stepUpSuccesses++
		case result.name == "step-up" && result.status == http.StatusUnauthorized:
		case result.name == "TOTP disable" && result.status == http.StatusNoContent:
			deleteSuccesses++
		case result.name == "TOTP disable" && result.status == http.StatusUnauthorized:
		default:
			t.Fatalf("%s result = %d: %s", result.name, result.status, result.body)
		}
	}
	if stepUpSuccesses+deleteSuccesses != 1 {
		t.Fatalf("step-up and TOTP disable succeeded %d times, want exactly once", stepUpSuccesses+deleteSuccesses)
	}
}

func addStepUpTestTOTPCredential(t *testing.T, stack *integrationStack, userID, secret string) {
	t.Helper()
	if _, err := store.CreateCredential(context.Background(), stack.database.pool, store.Credential{
		UserID: userID, Kind: "totp", Hash: secret,
	}); err != nil {
		t.Fatalf("create TOTP credential: %v", err)
	}
}
