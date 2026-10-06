package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"sort"
	"strings"
	"testing"

	"github.com/fxamacker/cbor/v2"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"teamusers/internal/store"
)

type passkeyListItem struct {
	ID        string `json:"id"`
	CreatedAt string `json:"created_at"`
}

type passkeyListResponse struct {
	Items      []passkeyListItem `json:"items"`
	NextCursor string            `json:"next_cursor"`
}

func TestPasskeyHTTPPaths(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "passkey-http", "passkey-password")
	accessToken := loginUser(t, stack, user.Username, "passkey-password")

	status, body := stack.jsonRequest(t, http.MethodPost, "/me/passkeys/register/begin", map[string]any{}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("register begin status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var begin struct {
		PublicKey struct {
			Challenge   string `json:"challenge"`
			Attestation string `json:"attestation"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &begin)
	if begin.PublicKey.Challenge == "" || begin.PublicKey.Attestation != "none" {
		t.Fatalf("register options = %+v, want challenge and none attestation", begin.PublicKey)
	}

	status, body = stack.rawRequest(t, http.MethodPost, "/me/passkeys/register/finish", []byte(`{"garbage":true}`), accessToken, nil)
	if status != http.StatusBadRequest {
		t.Fatalf("garbage register finish status = %d, want %d: %s", status, http.StatusBadRequest, body)
	}
	var problem struct {
		Title  string `json:"title"`
		Status int    `json:"status"`
	}
	decodeResponse(t, body, &problem)
	if problem.Status != http.StatusBadRequest || problem.Title != "Invalid Request" {
		t.Fatalf("garbage register finish problem = %+v, want Invalid Request 400", problem)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me/passkeys", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("empty passkey list status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var page passkeyListResponse
	decodeResponse(t, body, &page)
	if page.Items == nil || len(page.Items) != 0 || page.NextCursor != "" {
		t.Fatalf("empty passkey page = %+v, want empty items and cursor", page)
	}

	status, _ = stack.jsonRequest(t, http.MethodDelete, "/me/passkeys/AQ", nil, accessToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown passkey delete status = %d, want %d", status, http.StatusNotFound)
	}

	status, body = stack.rawRequest(t, http.MethodPost, "/auth/passkey/login/begin", nil, "", map[string]string{
		"Content-Type": "application/json",
	})
	if status != http.StatusOK {
		t.Fatalf("empty-body passkey login begin status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", map[string]string{
		"username": "does-not-exist",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown passkey login begin status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if len(body) == 0 || bytes.Contains(body, []byte("does-not-exist")) {
		t.Fatalf("unknown passkey login response leaked username: %s", body)
	}
	var method, result, attemptedUsername string
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT method, result, attempted_username FROM login_activity
		WHERE user_id IS NULL AND attempted_username = $1
		ORDER BY id DESC LIMIT 1`, "does-not-exist").Scan(&method, &result, &attemptedUsername); err != nil {
		t.Fatalf("read unresolved passkey failure: %v", err)
	}
	if method != "passkey" || result != "failure" || attemptedUsername != "does-not-exist" {
		t.Fatalf("unresolved passkey activity = %q/%q/%q, want passkey failure with attempted username", method, result, attemptedUsername)
	}
}

func TestPasskeyListPagination(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "passkey-pagination", "PasskeyPaginationPassword1")
	accessToken := loginUser(t, stack, user.Username, "PasskeyPaginationPassword1")
	otherUser := seedPasswordUser(t, ctx, stack.database.pool, "passkey-pagination-other", "OtherPasskeyPaginationPassword1")
	otherAccessToken := loginUser(t, stack, otherUser.Username, "OtherPasskeyPaginationPassword1")

	const credentialCount = 1004
	credentials := make([]webauthnlib.Credential, credentialCount)
	expectedIDs := make([]string, credentialCount)
	for index := range credentials {
		id := []byte{byte(index >> 8), byte(index)}
		credentials[index] = webauthnlib.Credential{
			ID:        id,
			PublicKey: []byte("sensitive-passkey-public-key"),
		}
		expectedIDs[index] = base64.RawURLEncoding.EncodeToString(id)
	}
	sort.Strings(expectedIDs)
	encodedCredentials, err := json.Marshal(credentials)
	if err != nil {
		t.Fatalf("encode passkey credentials: %v", err)
	}
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: user.ID, Kind: store.PasskeyCredentialKind, Hash: string(encodedCredentials),
	}); err != nil {
		t.Fatalf("create passkey credentials: %v", err)
	}

	otherCredential := webauthnlib.Credential{ID: []byte{0xfe, 0xff}}
	encodedOtherCredential, err := json.Marshal([]webauthnlib.Credential{otherCredential})
	if err != nil {
		t.Fatalf("encode other user's passkey credential: %v", err)
	}
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: otherUser.ID, Kind: store.PasskeyCredentialKind, Hash: string(encodedOtherCredential),
	}); err != nil {
		t.Fatalf("create other user's passkey credential: %v", err)
	}

	getPage := func(path, token string) (passkeyListResponse, []byte) {
		t.Helper()
		status, body := stack.jsonRequest(t, http.MethodGet, path, nil, token)
		if status != http.StatusOK {
			t.Fatalf("GET %s status = %d, want %d: %s", path, status, http.StatusOK, body)
		}
		var page passkeyListResponse
		decodeResponse(t, body, &page)
		if page.Items == nil {
			t.Fatalf("GET %s returned null items: %s", path, body)
		}
		return page, body
	}

	defaultPage, _ := getPage("/me/passkeys", accessToken)
	if len(defaultPage.Items) != 100 || defaultPage.NextCursor != expectedIDs[99] {
		t.Fatalf("default passkey page = %d items, cursor %q; want 100 items, cursor %q", len(defaultPage.Items), defaultPage.NextCursor, expectedIDs[99])
	}
	for index, item := range defaultPage.Items {
		if item.ID != expectedIDs[index] {
			t.Fatalf("default passkey item %d = %q, want %q", index, item.ID, expectedIDs[index])
		}
	}

	firstPage, firstBody := getPage("/me/passkeys?limit=2000", accessToken)
	if len(firstPage.Items) != 1000 || firstPage.NextCursor != expectedIDs[999] {
		t.Fatalf("clamped passkey page = %d items, cursor %q; want 1000 items, cursor %q", len(firstPage.Items), firstPage.NextCursor, expectedIDs[999])
	}
	encodedPublicKey := base64.StdEncoding.EncodeToString([]byte("sensitive-passkey-public-key"))
	if bytes.Contains(firstBody, []byte(encodedPublicKey)) {
		t.Fatal("passkey response exposed stored public-key material")
	}
	seen := make(map[string]struct{}, credentialCount)
	assertPageIDs := func(page passkeyListResponse, offset int) {
		for index, item := range page.Items {
			if want := expectedIDs[offset+index]; item.ID != want {
				t.Fatalf("passkey item %d after offset %d = %q, want %q", index, offset, item.ID, want)
			}
			if item.CreatedAt == "" {
				t.Fatalf("passkey item %q has no created_at", item.ID)
			}
			if _, exists := seen[item.ID]; exists {
				t.Fatalf("passkey page repeated credential %q", item.ID)
			}
			seen[item.ID] = struct{}{}
		}
	}
	assertPageIDs(firstPage, 0)

	secondPage, _ := getPage("/me/passkeys?limit=2000&cursor="+firstPage.NextCursor, accessToken)
	if len(secondPage.Items) != credentialCount-1000 || secondPage.NextCursor != "" {
		t.Fatalf("short terminal passkey page = %d items, cursor %q; want %d items and empty cursor", len(secondPage.Items), secondPage.NextCursor, credentialCount-1000)
	}
	assertPageIDs(secondPage, 1000)
	if len(seen) != credentialCount {
		t.Fatalf("keyset pages returned %d distinct passkeys, want %d", len(seen), credentialCount)
	}

	exactPage, _ := getPage("/me/passkeys?cursor="+expectedIDs[3]+"&limit=1000", accessToken)
	if len(exactPage.Items) != 1000 || exactPage.NextCursor != expectedIDs[credentialCount-1] {
		t.Fatalf("exact terminal-size page = %d items, cursor %q; want 1000 items and last ID cursor %q", len(exactPage.Items), exactPage.NextCursor, expectedIDs[credentialCount-1])
	}
	for index, item := range exactPage.Items {
		if want := expectedIDs[index+4]; item.ID != want {
			t.Fatalf("exact terminal-size item %d = %q, want %q", index, item.ID, want)
		}
	}
	emptyPage, _ := getPage("/me/passkeys?cursor="+exactPage.NextCursor+"&limit=1000", accessToken)
	if len(emptyPage.Items) != 0 || emptyPage.NextCursor != "" {
		t.Fatalf("empty terminal passkey page = %+v, want empty items and cursor", emptyPage)
	}

	otherPage, _ := getPage("/me/passkeys", otherAccessToken)
	otherID := base64.RawURLEncoding.EncodeToString(otherCredential.ID)
	if len(otherPage.Items) != 1 || otherPage.Items[0].ID != otherID || otherPage.NextCursor != "" {
		t.Fatalf("other user's passkey page = %+v, want only %q", otherPage, otherID)
	}

	for _, path := range []string{"/me/passkeys?cursor=not-valid", "/me/passkeys?limit=0"} {
		status, body := stack.jsonRequest(t, http.MethodGet, path, nil, accessToken)
		if status != http.StatusBadRequest {
			t.Fatalf("GET %s status = %d, want %d: %s", path, status, http.StatusBadRequest, body)
		}
		var problem struct {
			Title  string `json:"title"`
			Status int    `json:"status"`
		}
		decodeResponse(t, body, &problem)
		if problem.Status != http.StatusBadRequest || problem.Title != "Invalid Request" {
			t.Fatalf("GET %s problem = %+v, want Invalid Request 400", path, problem)
		}
	}
}

func TestPasskeyCeremonyWithSoftAuthenticator(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "passkey-ceremony", "passkey-password")
	accessToken := loginUser(t, stack, user.Username, "passkey-password")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}
	registerSoftPasskey(t, stack, accessToken, privateKey, credentialID)
	status, body := stack.jsonRequest(t, http.MethodGet, "/me/passkeys", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("passkey list status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var page passkeyListResponse
	decodeResponse(t, body, &page)
	if len(page.Items) != 1 || page.Items[0].ID != base64.RawURLEncoding.EncodeToString(credentialID) || page.NextCursor != "" {
		t.Fatalf("passkey page = %+v, want one credential %s and empty cursor", page, base64.RawURLEncoding.EncodeToString(credentialID))
	}

	status, body = loginWithSoftPasskey(t, stack, user.Username, user.ID, credentialID, privateKey, false)
	if status != http.StatusOK {
		t.Fatalf("login finish status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	status, body = stack.jsonRequest(t, http.MethodGet, "/me/activity", nil, pair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("passkey activity status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var activity struct {
		Items []struct {
			Method string `json:"method"`
			Result string `json:"result"`
		} `json:"items"`
	}
	decodeResponse(t, body, &activity)
	if len(activity.Items) == 0 || activity.Items[0].Method != "passkey" || activity.Items[0].Result != "success" {
		t.Fatalf("latest passkey activity = %+v, want passkey success", activity.Items)
	}
}

func TestPasskeyLoginMFACombinations(t *testing.T) {
	cases := []struct {
		name                         string
		username                     string
		assertionUserVerified        bool
		storedCredentialUserVerified bool
		hasTOTP                      bool
		requiredPolicy               bool
		optionalPolicy               bool
		denyUnenrolled               bool
		want                         string
	}{
		{name: "UV no TOTP no policy", username: "passkey-mfa-uv-no-totp-no-policy", assertionUserVerified: true, want: "tokens"},
		{name: "UV TOTP no policy", username: "passkey-mfa-uv-totp-no-policy", assertionUserVerified: true, storedCredentialUserVerified: false, hasTOTP: true, want: "tokens"},
		{name: "UV no TOTP required policy", username: "passkey-mfa-uv-no-totp-policy", assertionUserVerified: true, requiredPolicy: true, want: "tokens"},
		{name: "UV TOTP required policy", username: "passkey-mfa-uv-totp-policy", assertionUserVerified: true, hasTOTP: true, requiredPolicy: true, want: "tokens"},
		{name: "non-UV no TOTP no policy", username: "passkey-mfa-nouv-no-totp-no-policy", want: "tokens"},
		{name: "non-UV no TOTP optional policy", username: "passkey-mfa-nouv-no-totp-optional-policy", optionalPolicy: true, want: "tokens"},
		{name: "non-UV TOTP no policy", username: "passkey-mfa-nouv-totp-no-policy", hasTOTP: true, want: "mfa"},
		{name: "non-UV no TOTP required policy", username: "passkey-mfa-nouv-no-totp-policy", requiredPolicy: true, want: "enrollment"},
		{name: "non-UV TOTP required policy", username: "passkey-mfa-nouv-totp-policy", hasTOTP: true, requiredPolicy: true, want: "mfa"},
		{name: "non-UV denied required enrollment", username: "passkey-mfa-nouv-denied-enrollment", requiredPolicy: true, denyUnenrolled: true, want: "denied"},
		{name: "non-UV stored UV no TOTP no policy", username: "passkey-mfa-nouv-stored-uv-no-policy", storedCredentialUserVerified: true, want: "tokens"},
		{name: "non-UV stored UV TOTP no policy", username: "passkey-mfa-nouv-stored-uv-totp", storedCredentialUserVerified: true, hasTOTP: true, want: "mfa"},
		{name: "non-UV stored UV required enrollment", username: "passkey-mfa-nouv-stored-uv-enrollment", storedCredentialUserVerified: true, requiredPolicy: true, want: "enrollment"},
		{name: "non-UV stored UV denied enrollment", username: "passkey-mfa-nouv-stored-uv-denied-enrollment", storedCredentialUserVerified: true, requiredPolicy: true, denyUnenrolled: true, want: "denied"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			stack := newIntegrationStack(t)
			ctx := context.Background()
			user := seedPasswordUser(t, ctx, stack.database.pool, testCase.username, "passkey-mfa-password")
			accessToken := loginUser(t, stack, user.Username, "passkey-mfa-password")
			privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
			if err != nil {
				t.Fatalf("generate soft authenticator key: %v", err)
			}
			credentialID := make([]byte, 32)
			if _, err := rand.Read(credentialID); err != nil {
				t.Fatalf("generate soft authenticator credential id: %v", err)
			}
			registerSoftPasskey(t, stack, accessToken, privateKey, credentialID)
			seedPasskeyCredentialUserVerified(t, ctx, stack, user.ID, testCase.storedCredentialUserVerified)

			if testCase.hasTOTP {
				if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
					UserID: user.ID, Kind: "totp", Hash: "passkey-mfa-totp-seed",
				}); err != nil {
					t.Fatalf("create TOTP credential: %v", err)
				}
			}
			policyID := ""
			if testCase.requiredPolicy || testCase.optionalPolicy {
				policy, err := store.CreateMFAPolicy(ctx, stack.database.pool, store.MFAPolicy{
					Name: "passkey MFA " + testCase.username, Priority: 100, SubjectKind: "default",
					Required: testCase.requiredPolicy, DenyUnenrolled: testCase.denyUnenrolled,
				})
				if err != nil {
					t.Fatalf("create MFA policy: %v", err)
				}
				policyID = policy.ID
			}

			status, body := loginWithSoftPasskey(t, stack, user.Username, user.ID, credentialID, privateKey, testCase.assertionUserVerified)
			if policyID != "" {
				if err := store.DeleteMFAPolicy(ctx, stack.database.pool, policyID); err != nil {
					t.Fatalf("delete MFA policy: %v", err)
				}
			}
			wantAMR := []string{"webauthn"}
			if testCase.assertionUserVerified {
				wantAMR = append(wantAMR, "mfa")
			}
			switch testCase.want {
			case "tokens":
				if status != http.StatusOK {
					t.Fatalf("login finish status = %d, want %d", status, http.StatusOK)
				}
				var pair tokenPair
				if err := json.Unmarshal(body, &pair); err != nil {
					t.Fatalf("decode passkey token response: %v", err)
				}
				if pair.AccessToken == "" || pair.RefreshToken == "" || pair.TokenType != "Bearer" || pair.ExpiresIn <= 0 {
					t.Fatalf("invalid passkey token pair: access_token_present=%t, refresh_token_present=%t, token_type=%q, expires_in=%d",
						pair.AccessToken != "", pair.RefreshToken != "", pair.TokenType, pair.ExpiresIn)
				}
				var claims struct {
					AMR []string `json:"amr"`
				}
				decodeTokenClaims(t, pair.AccessToken, &claims)
				if strings.Join(claims.AMR, ",") != strings.Join(wantAMR, ",") {
					t.Fatalf("passkey access-token AMR = %v, want %v from the signed assertion", claims.AMR, wantAMR)
				}
			case "mfa":
				var challenge struct {
					MFARequired  bool     `json:"mfa_required"`
					MFAToken     string   `json:"mfa_token"`
					MFAMethods   []string `json:"mfa_methods"`
					AccessToken  string   `json:"access_token"`
					RefreshToken string   `json:"refresh_token"`
				}
				if status != http.StatusOK {
					t.Fatalf("login finish status = %d, want %d", status, http.StatusOK)
				}
				if err := json.Unmarshal(body, &challenge); err != nil {
					t.Fatalf("decode passkey MFA response: %v", err)
				}
				if !challenge.MFARequired || challenge.MFAToken == "" || len(challenge.MFAMethods) != 1 || challenge.MFAMethods[0] != "otp" || challenge.AccessToken != "" || challenge.RefreshToken != "" {
					t.Fatalf("passkey login challenge = required:%t token_present:%t methods:%v access_token_present:%t refresh_token_present:%t; want TOTP challenge without full tokens",
						challenge.MFARequired, challenge.MFAToken != "", challenge.MFAMethods, challenge.AccessToken != "", challenge.RefreshToken != "")
				}
				var pending struct {
					Purpose string   `json:"purpose"`
					AMR     []string `json:"amr"`
				}
				decodeTokenClaims(t, challenge.MFAToken, &pending)
				if pending.Purpose != "mfa" || strings.Join(pending.AMR, ",") != strings.Join(wantAMR, ",") {
					t.Fatalf("passkey MFA token evidence = purpose:%q amr:%v, want purpose:mfa amr:%v", pending.Purpose, pending.AMR, wantAMR)
				}
			case "enrollment":
				var enrollment struct {
					Required     bool     `json:"mfa_enrollment_required"`
					MFAToken     string   `json:"mfa_token"`
					MFAMethods   []string `json:"mfa_methods"`
					AccessToken  string   `json:"access_token"`
					RefreshToken string   `json:"refresh_token"`
				}
				if status != http.StatusOK {
					t.Fatalf("login finish status = %d, want %d", status, http.StatusOK)
				}
				if err := json.Unmarshal(body, &enrollment); err != nil {
					t.Fatalf("decode passkey enrollment response: %v", err)
				}
				if !enrollment.Required || enrollment.MFAToken == "" || len(enrollment.MFAMethods) != 1 || enrollment.MFAMethods[0] != "otp" || enrollment.AccessToken != "" || enrollment.RefreshToken != "" {
					t.Fatalf("passkey enrollment response = required:%t token_present:%t methods:%v access_token_present:%t refresh_token_present:%t; want restricted enrollment challenge without full tokens",
						enrollment.Required, enrollment.MFAToken != "", enrollment.MFAMethods, enrollment.AccessToken != "", enrollment.RefreshToken != "")
				}
				var pending struct {
					Purpose string   `json:"purpose"`
					AMR     []string `json:"amr"`
				}
				decodeTokenClaims(t, enrollment.MFAToken, &pending)
				if pending.Purpose != "mfa_enroll" || strings.Join(pending.AMR, ",") != strings.Join(wantAMR, ",") {
					t.Fatalf("passkey enrollment token evidence = purpose:%q amr:%v, want purpose:mfa_enroll amr:%v", pending.Purpose, pending.AMR, wantAMR)
				}
			case "denied":
				denialCodePresent := strings.Contains(string(body), "mfa_enrollment_denied")
				if status != http.StatusForbidden || !denialCodePresent {
					t.Fatalf("login finish status = %d, denial_code_present=%t; want mfa_enrollment_denied 403", status, denialCodePresent)
				}
			}
		})
	}
}

func TestPasskeyBeginDecodeFailureRespectsIPRateLimit(t *testing.T) {
	stack := newIntegrationStack(t)
	for attempt := range 30 {
		status, body := stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", "not-an-object", "")
		if status != http.StatusUnauthorized {
			t.Fatalf("malformed passkey begin attempt %d status = %d, want %d: %s", attempt+1, status, http.StatusUnauthorized, body)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", "not-an-object", "")
	if status != http.StatusTooManyRequests {
		t.Fatalf("rate-limited passkey begin status = %d, want %d: %s", status, http.StatusTooManyRequests, body)
	}
	var recordedFailures int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM login_activity
		WHERE user_id IS NULL AND method = 'passkey' AND result = 'failure'`).Scan(&recordedFailures); err != nil {
		t.Fatalf("count malformed passkey activity: %v", err)
	}
	if recordedFailures != 30 {
		t.Fatalf("malformed passkey activity rows = %d, want 30 limiter-passed attempts", recordedFailures)
	}
}

func TestPasskeyMFAResetsFailedLoginsOnlyAfterCompletion(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "passkey-mfa-lockout", "PasskeyMFApassword1")
	accessToken := loginUser(t, stack, user.Username, "PasskeyMFApassword1")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}
	registerSoftPasskey(t, stack, accessToken, privateKey, credentialID)
	const totpSecret = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: user.ID, Kind: "totp", Hash: totpSecret,
	}); err != nil {
		t.Fatalf("create TOTP credential: %v", err)
	}
	if _, err := stack.database.pool.Exec(ctx, `UPDATE users SET failed_logins = 1 WHERE id = $1`, user.ID); err != nil {
		t.Fatalf("seed failed login count: %v", err)
	}

	status, body := loginWithSoftPasskey(t, stack, user.Username, user.ID, credentialID, privateKey, false)
	if status != http.StatusOK {
		t.Fatalf("passkey MFA first-factor status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var challenge struct {
		MFARequired bool   `json:"mfa_required"`
		MFAToken    string `json:"mfa_token"`
	}
	decodeResponse(t, body, &challenge)
	if !challenge.MFARequired || challenge.MFAToken == "" {
		t.Fatalf("passkey login response = %s, want MFA challenge", body)
	}
	var failedLogins int
	if err := stack.database.pool.QueryRow(ctx, `SELECT failed_logins FROM users WHERE id = $1`, user.ID).Scan(&failedLogins); err != nil {
		t.Fatalf("read failed login count after passkey factor: %v", err)
	}
	if failedLogins != 1 {
		t.Fatalf("failed login count after passkey factor = %d, want 1 until MFA completes", failedLogins)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      "00000x",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("passkey MFA invalid TOTP status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if err := stack.database.pool.QueryRow(ctx, `SELECT failed_logins FROM users WHERE id = $1`, user.ID).Scan(&failedLogins); err != nil {
		t.Fatalf("read failed login count after invalid TOTP: %v", err)
	}
	if failedLogins != 2 {
		t.Fatalf("failed login count after invalid TOTP = %d, want 2 without reset", failedLogins)
	}
	code, err := currentTOTPCode(t, totpSecret)
	if err != nil {
		t.Fatalf("generate TOTP code: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      code,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("passkey MFA completion status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	if err := stack.database.pool.QueryRow(ctx, `SELECT failed_logins FROM users WHERE id = $1`, user.ID).Scan(&failedLogins); err != nil {
		t.Fatalf("read failed login count after MFA completion: %v", err)
	}
	if failedLogins != 0 {
		t.Fatalf("failed login count after MFA completion = %d, want 0", failedLogins)
	}
}

func registerSoftPasskey(t *testing.T, stack *integrationStack, accessToken string, privateKey *ecdsa.PrivateKey, credentialID []byte) {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/me/passkeys/register/begin", map[string]any{}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("register begin status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var creation struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &creation)
	if creation.PublicKey.Challenge == "" {
		t.Fatal("register begin returned an empty challenge")
	}
	registerClientData := clientDataJSON("webauthn.create", creation.PublicKey.Challenge, "http://localhost")
	registerAuthenticatorData := registrationAuthenticatorData("localhost", credentialID, privateKey.PublicKey)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": registerAuthenticatorData,
	})
	if err != nil {
		t.Fatalf("encode soft authenticator attestation: %v", err)
	}
	registerResponse := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(registerClientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/passkeys/register/finish", registerResponse, accessToken)
	if status != http.StatusNoContent {
		t.Fatalf("register finish status = %d, want %d: %s", status, http.StatusNoContent, body)
	}
}

func seedPasskeyCredentialUserVerified(t *testing.T, ctx context.Context, stack *integrationStack, userID string, userVerified bool) {
	t.Helper()
	credentials, err := store.GetPasskeys(ctx, stack.database.pool, userID)
	if err != nil {
		t.Fatalf("load registered passkey credential: %v", err)
	}
	if len(credentials) != 1 {
		t.Fatalf("registered passkey credential count = %d, want 1", len(credentials))
	}
	credentials[0].Flags.UserVerified = userVerified
	if err := store.UpdatePasskey(ctx, stack.database.pool, userID, credentials[0]); err != nil {
		t.Fatalf("seed passkey credential user-verification state: %v", err)
	}
}

func loginWithSoftPasskey(t *testing.T, stack *integrationStack, username, userID string, credentialID []byte, privateKey *ecdsa.PrivateKey, assertionUserVerified bool) (int, []byte) {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", map[string]string{
		"username": username,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login begin status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var assertion struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &assertion)
	if assertion.PublicKey.Challenge == "" {
		t.Fatal("login begin returned an empty challenge")
	}
	loginClientData := clientDataJSON("webauthn.get", assertion.PublicKey.Challenge, "http://localhost")
	loginAuthenticatorData := assertionAuthenticatorData("localhost", 1, assertionUserVerified)
	clientDataHash := sha256.Sum256(loginClientData)
	signedData := append(append([]byte(nil), loginAuthenticatorData...), clientDataHash[:]...)
	assertionHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, assertionHash[:])
	if err != nil {
		t.Fatalf("sign soft authenticator assertion: %v", err)
	}
	loginResponse := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(loginClientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(loginAuthenticatorData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString([]byte(userID)),
		},
	}
	return stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/finish", loginResponse, "")
}

func clientDataJSON(kind, challenge, origin string) []byte {
	body, _ := json.Marshal(map[string]string{
		"type":      kind,
		"challenge": challenge,
		"origin":    origin,
	})
	return body
}

func registrationAuthenticatorData(rpid string, credentialID []byte, publicKey ecdsa.PublicKey) []byte {
	rpIDHash := sha256.Sum256([]byte(rpid))
	data := make([]byte, 0, 128)
	data = append(data, rpIDHash[:]...)
	data = append(data, 0x41, 0, 0, 0, 0)
	data = append(data, make([]byte, 16)...)
	data = append(data, byte(len(credentialID)>>8), byte(len(credentialID)))
	data = append(data, credentialID...)
	coseKey, _ := cbor.Marshal(map[int]any{
		1:  int64(2),
		3:  int64(-7),
		-1: int64(1),
		-2: paddedBytes(publicKey.X, 32),
		-3: paddedBytes(publicKey.Y, 32),
	})
	return append(data, coseKey...)
}

func assertionAuthenticatorData(rpid string, counter uint32, userVerified bool) []byte {
	rpIDHash := sha256.Sum256([]byte(rpid))
	flags := byte(0x01)
	if userVerified {
		flags |= 0x04
	}
	return append(rpIDHash[:], flags, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
}

func paddedBytes(value *big.Int, size int) []byte {
	encoded := value.Bytes()
	result := make([]byte, size)
	copy(result[size-len(encoded):], encoded)
	return result
}
