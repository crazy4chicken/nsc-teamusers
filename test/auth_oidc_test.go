package test

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"teamusers/internal/config"
	"teamusers/internal/store"
)

const (
	testOIDCClientID     = "teamusers-test-client"
	testOIDCClientSecret = "teamusers-test-secret"
	testOIDCRedirectURL  = "http://teamusers.example/auth/oidc/callback"
	testOIDCStateCookieName = "__Host-oidc_state"
)

type mockOIDCSigningKey struct {
	kid     string
	public  ed25519.PublicKey
	private ed25519.PrivateKey
}

type queuedOIDCToken struct {
	idToken       string
	codeChallenge string
}

type mockOIDCProvider struct {
	server       *httptest.Server
	clientID     string
	clientSecret string
	redirectURL  string
	issuerPath   string

	mu            sync.Mutex
	keys          []mockOIDCSigningKey
	omitJWKAlgorithm bool
	tokens                   map[string]queuedOIDCToken
	nextCode      int
	exchanges     int
	jwksRequests  int
	redirectTokenResponse bool
	redirectTargetRequests int
}

func newMockOIDCProvider(t *testing.T, issuerPath string) *mockOIDCProvider {
	t.Helper()
	key := newMockOIDCSigningKey(t, "idp-key-1")
	issuerPath = strings.Trim(issuerPath, "/")
	if issuerPath != "" {
		issuerPath = "/" + issuerPath
	}
	provider := &mockOIDCProvider{
		clientID:     testOIDCClientID,
		clientSecret: testOIDCClientSecret,
		redirectURL:  testOIDCRedirectURL,
		issuerPath:   issuerPath,
		keys:         []mockOIDCSigningKey{key},
		tokens:       make(map[string]queuedOIDCToken),
	}
	provider.server = httptest.NewServer(http.HandlerFunc(provider.serveHTTP))
	t.Cleanup(provider.server.Close)
	return provider
}

func (p *mockOIDCProvider) issuerURL() string {
	return p.server.URL + p.issuerPath
}

func (p *mockOIDCProvider) serveHTTP(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	switch r.URL.Path {
	case p.issuerPath + "/.well-known/openid-configuration":
		_ = json.NewEncoder(w).Encode(map[string]string{
			"issuer":                 p.issuerURL(),
			"authorization_endpoint": p.issuerURL() + "/authorize",
			"token_endpoint":         p.issuerURL() + "/token",
			"jwks_uri":               p.issuerURL() + "/jwks",
		})
	case p.issuerPath + "/jwks":
		p.mu.Lock()
		p.jwksRequests++
		keys := append([]mockOIDCSigningKey(nil), p.keys...)
		omitAlgorithm := p.omitJWKAlgorithm
		p.mu.Unlock()
		set := make([]map[string]string, 0, len(keys))
		for _, key := range keys {
			jwk := map[string]string{
				"kty": "OKP", "crv": "Ed25519", "kid": key.kid, "use": "sig",
				"x": base64.RawURLEncoding.EncodeToString(key.public),
			}
			if !omitAlgorithm {
				jwk["alg"] = "EdDSA"
			}
			set = append(set, jwk)
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"keys": set})
	case p.issuerPath + "/token":
		clientID, clientSecret, ok := r.BasicAuth()
		if !ok || clientID != p.clientID || clientSecret != p.clientSecret {
			http.Error(w, `{"error":"invalid_client"}`, http.StatusUnauthorized)
			return
		}
		if err := r.ParseForm(); err != nil || r.Form.Get("grant_type") != "authorization_code" || r.Form.Get("redirect_uri") != p.redirectURL {
			http.Error(w, `{"error":"invalid_request"}`, http.StatusBadRequest)
			return
		}
		p.mu.Lock()
		p.exchanges++
		redirect := p.redirectTokenResponse
		token := p.tokens[r.Form.Get("code")]
		delete(p.tokens, r.Form.Get("code"))
		p.mu.Unlock()
		if redirect {
			http.Redirect(w, r, p.issuerURL()+"/token-redirect-target", http.StatusFound)
			return
		}
		codeVerifier := r.Form.Get("code_verifier")
		if token.idToken == "" || codeVerifier == "" || (token.codeChallenge != "" && mockOIDCCodeChallenge(codeVerifier) != token.codeChallenge) {
			http.Error(w, `{"error":"invalid_grant"}`, http.StatusBadRequest)
			return
		}
		_ = json.NewEncoder(w).Encode(map[string]string{
			"token_type": "Bearer",
			"id_token":   token.idToken,
		})
	case p.issuerPath + "/token-redirect-target":
		p.mu.Lock()
		p.redirectTargetRequests++
		p.mu.Unlock()
		w.WriteHeader(http.StatusNoContent)
	default:
		http.NotFound(w, r)
	}
}

func newOIDCIntegrationStack(t *testing.T, registrationMode string) (*integrationStack, *mockOIDCProvider) {
	return newOIDCIntegrationStackAtIssuerPath(t, registrationMode, "")
}

func newOIDCIntegrationStackAtIssuerPath(t *testing.T, registrationMode, issuerPath string) (*integrationStack, *mockOIDCProvider) {
	return newOIDCIntegrationStackAtIssuerPathWithConfig(t, registrationMode, issuerPath, nil)
}

func newOIDCIntegrationStackWithConfig(t *testing.T, registrationMode string, configure func(*config.Config)) (*integrationStack, *mockOIDCProvider) {
	return newOIDCIntegrationStackAtIssuerPathWithConfig(t, registrationMode, "", configure)
}

func newOIDCIntegrationStackAtIssuerPathWithConfig(t *testing.T, registrationMode, issuerPath string, configure func(*config.Config)) (*integrationStack, *mockOIDCProvider) {
	t.Helper()
	provider := newMockOIDCProvider(t, issuerPath)
	stack := newIntegrationStackWithModeAndConfig(t, registrationMode, func(cfg *config.Config) {
		cfg.OIDCIssuer = provider.issuerURL()
		cfg.OIDCClientID = provider.clientID
		cfg.OIDCClientSecret = provider.clientSecret
		cfg.OIDCRedirectURL = provider.redirectURL
		if configure != nil {
			configure(cfg)
		}
	})
	return stack, provider
}

func (p *mockOIDCProvider) queueIDToken(
	t *testing.T,
	nonce, subject, email string,
	emailVerified bool,
	amr []string,
	key mockOIDCSigningKey,
	overrides map[string]any,
	expectedCodeChallenge ...string,
) string {
	t.Helper()
	now := time.Now().UTC()
	claims := map[string]any{
		"iss":            p.issuerURL(),
		"sub":            subject,
		"aud":            p.clientID,
		"exp":            now.Add(5 * time.Minute).Unix(),
		"iat":            now.Unix(),
		"nonce":          nonce,
		"email":          email,
		"email_verified": emailVerified,
		"name":           "OIDC " + subject,
		"amr":            amr,
	}
	for name, value := range overrides {
		claims[name] = value
	}
	header, err := json.Marshal(map[string]string{"alg": "EdDSA", "kid": key.kid, "typ": "JWT"})
	if err != nil {
		t.Fatalf("encode mock OIDC header: %v", err)
	}
	payload, err := json.Marshal(claims)
	if err != nil {
		t.Fatalf("encode mock OIDC claims: %v", err)
	}
	encodedHeader := base64.RawURLEncoding.EncodeToString(header)
	encodedPayload := base64.RawURLEncoding.EncodeToString(payload)
	signingInput := encodedHeader + "." + encodedPayload
	signature := ed25519.Sign(key.private, []byte(signingInput))
	idToken := signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)

	queued := queuedOIDCToken{idToken: idToken}
	if len(expectedCodeChallenge) > 0 {
		queued.codeChallenge = expectedCodeChallenge[0]
	}
	p.mu.Lock()
	p.nextCode++
	code := fmt.Sprintf("oidc-code-%d", p.nextCode)
	p.tokens[code] = queued
	p.mu.Unlock()
	return code
}

func (p *mockOIDCProvider) currentKey() mockOIDCSigningKey {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.keys[0]
}

func (p *mockOIDCProvider) setKeys(keys ...mockOIDCSigningKey) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.keys = append([]mockOIDCSigningKey(nil), keys...)
}

func (p *mockOIDCProvider) setJWKAlgorithmOmitted(omitted bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.omitJWKAlgorithm = omitted
}

func (p *mockOIDCProvider) counts() (jwksRequests, tokenExchanges int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.jwksRequests, p.exchanges
}

func (p *mockOIDCProvider) setTokenRedirect(enabled bool) {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.redirectTokenResponse = enabled
}

func (p *mockOIDCProvider) redirectTargetRequestCount() int {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.redirectTargetRequests
}

func newMockOIDCSigningKey(t *testing.T, kid string) mockOIDCSigningKey {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate mock OIDC signing key: %v", err)
	}
	return mockOIDCSigningKey{kid: kid, public: public, private: private}
}

func beginOIDCLogin(t *testing.T, stack *integrationStack) (state, nonce string) {
	state, nonce, _, _ = beginOIDCLoginWithDetails(t, stack)
	return state, nonce
}

func beginOIDCLoginWithDetails(t *testing.T, stack *integrationStack) (state, nonce, codeChallenge, cookieValue string) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), http.MethodGet, stack.baseURL+"/auth/oidc/begin", nil)
	if err != nil {
		t.Fatalf("build OIDC begin request: %v", err)
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	response, err := client.Do(request)
	if err != nil {
		t.Fatalf("perform OIDC begin request: %v", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusFound {
		body, _ := io.ReadAll(response.Body)
		t.Fatalf("OIDC begin status = %d, want %d: %s", response.StatusCode, http.StatusFound, body)
	}
	var stateCookie *http.Cookie
	for _, cookie := range response.Cookies() {
		if cookie.Name == testOIDCStateCookieName {
			if stateCookie != nil {
				t.Fatal("OIDC begin returned duplicate state cookies")
			}
			stateCookie = cookie
		}
	}
	if stateCookie == nil || !stateCookie.Secure || !stateCookie.HttpOnly || stateCookie.SameSite != http.SameSiteLaxMode || stateCookie.Path != "/" || stateCookie.Domain != "" {
		t.Fatalf("OIDC state cookie = %+v, want __Host- Secure HttpOnly SameSite=Lax Path=/ cookie without Domain", stateCookie)
	}
	location, err := url.Parse(response.Header.Get("Location"))
	if err != nil {
		t.Fatalf("parse OIDC authorization URL: %v", err)
	}
	query := location.Query()
	if query.Get("response_type") != "code" || query.Get("client_id") != testOIDCClientID || query.Get("redirect_uri") != testOIDCRedirectURL {
		t.Fatalf("OIDC authorization request parameters are incomplete: %v", query)
	}
	state, nonce = query.Get("state"), query.Get("nonce")
	codeChallenge = query.Get("code_challenge")
	if state == "" || nonce == "" || codeChallenge == "" || query.Get("code_challenge_method") != "S256" {
		t.Fatalf("OIDC authorization URL has empty state, nonce, or S256 challenge: %v", query)
	}
	if stateCookie.Value != testOIDCStateDigest(state) {
		t.Fatalf("OIDC state cookie = %q, want state digest %q", stateCookie.Value, testOIDCStateDigest(state))
	}
	return state, nonce, codeChallenge, stateCookie.Value
}

func mockOIDCCodeChallenge(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func testOIDCStateDigest(state string) string {
	digest := sha256.Sum256([]byte(state))
	return hex.EncodeToString(digest[:])
}

func completeOIDCLogin(t *testing.T, stack *integrationStack, state, code string) (int, []byte) {
	return completeOIDCLoginWithCookie(t, stack, state, code, testOIDCStateDigest(state))
}

func completeOIDCLoginWithCookie(t *testing.T, stack *integrationStack, state, code, cookieValue string) (int, []byte) {
	t.Helper()
	path := "/auth/oidc/callback?state=" + url.QueryEscape(state) + "&code=" + url.QueryEscape(code)
	headers := map[string]string{}
	if cookieValue != "" {
		headers["Cookie"] = testOIDCStateCookieName + "=" + cookieValue
	}
	return stack.jsonRequestHeaders(t, http.MethodGet, path, nil, "", headers)
}

func TestOIDCStateCookieBindsPKCECallback(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "open")
	state, nonce, codeChallenge, cookieValue := beginOIDCLoginWithDetails(t, stack)
	code := provider.queueIDToken(t, nonce, "subject-pkce", "pkce-user@example.test", true, []string{"pwd"}, provider.currentKey(), nil, codeChallenge)
	_, exchangesBefore := provider.counts()

	status, body := completeOIDCLoginWithCookie(t, stack, state, code, "wrong-cookie-value")
	if status != http.StatusUnauthorized {
		t.Fatalf("callback with mismatched state cookie = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	_, exchangesAfterMismatch := provider.counts()
	if exchangesAfterMismatch != exchangesBefore {
		t.Fatalf("mismatched state cookie performed %d token exchanges, want unchanged count %d", exchangesAfterMismatch, exchangesBefore)
	}

	status, body = completeOIDCLoginWithCookie(t, stack, state, code, cookieValue)
	if status != http.StatusOK {
		t.Fatalf("PKCE callback with matching state cookie = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	_, exchangesAfterSuccess := provider.counts()
	if exchangesAfterSuccess != exchangesBefore+1 {
		t.Fatalf("PKCE callback token exchanges = %d, want %d", exchangesAfterSuccess, exchangesBefore+1)
	}
}


type decodedAccessClaims struct {
	Subject  string   `json:"sub"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
}

func decodeAccessClaims(t *testing.T, raw string) decodedAccessClaims {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("access token has %d compact parts, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access-token claims: %v", err)
	}
	var claims decodedAccessClaims
	if err := json.Unmarshal(payload, &claims); err != nil {
		t.Fatalf("decode access-token claims JSON: %v", err)
	}
	return claims
}

func TestOIDCJITLoginIssuesTokenPairAndRefreshesUnknownKID(t *testing.T) {
	stack, provider := newOIDCIntegrationStackAtIssuerPath(t, "open", "/tenant/realm")
	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "subject-jit", "jit-user@example.test", true, []string{"pwd"}, provider.currentKey(), nil)
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("OIDC JIT callback status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	claims := decodeAccessClaims(t, pair.AccessToken)
	if claims.Subject == "" || claims.AuthTime <= 0 || len(claims.AMR) != 1 || claims.AMR[0] != "ext" {
		t.Fatalf("OIDC access-token claims = %+v, want user subject, auth_time, and ext evidence", claims)
	}

	ctx := context.Background()
	user, err := store.GetOIDCUserByEmail(ctx, stack.database.pool, "jit-user@example.test")
	if err != nil {
		t.Fatalf("read JIT-provisioned user: %v", err)
	}
	if user.Status != "active" || user.EmailVerifiedAt == nil || user.ID != claims.Subject {
		t.Fatalf("JIT user = %+v, want active verified user matching token subject", user)
	}
	linkedUserID, err := store.GetOIDCIdentity(ctx, stack.database.pool, provider.issuerURL(), "subject-jit")
	if err != nil || linkedUserID != user.ID {
		t.Fatalf("OIDC identity user = %q, error = %v, want %q", linkedUserID, err, user.ID)
	}
	var lifecycleEvents, identityAudits int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM outbox
		WHERE topic = 'user.created' AND payload->>'user_id' = $1`, user.ID).Scan(&lifecycleEvents); err != nil {
		t.Fatalf("count OIDC user.created lifecycle events: %v", err)
	}
	if lifecycleEvents != 1 {
		t.Fatalf("OIDC user.created lifecycle event count = %d, want 1", lifecycleEvents)
	}
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_log
		WHERE action = 'auth.oidc.identity_linked' AND target = $1`, user.ID).Scan(&identityAudits); err != nil {
		t.Fatalf("count OIDC identity-link audit rows: %v", err)
	}
	if identityAudits != 1 {
		t.Fatalf("OIDC identity-link audit count = %d, want 1", identityAudits)
	}
	var method, result string
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT method, result FROM login_activity
		WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, user.ID).Scan(&method, &result); err != nil {
		t.Fatalf("read OIDC login activity: %v", err)
	}
	if method != "oidc" || result != "success" {
		t.Fatalf("OIDC login activity = %q/%q, want oidc success", method, result)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": pair.RefreshToken}, "")
	if status != http.StatusOK {
		t.Fatalf("OIDC refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var rotated tokenPair
	decodeResponse(t, body, &rotated)
	assertTokenPair(t, rotated)

	jwksBefore, _ := provider.counts()
	rotatedKey := newMockOIDCSigningKey(t, "idp-key-2")
	provider.setKeys(rotatedKey)
	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "subject-jit", "jit-user@example.test", true, []string{"pwd"}, rotatedKey, nil)
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("OIDC callback after JWKS key rotation = %d, want %d: %s", status, http.StatusOK, body)
	}
	jwksAfter, _ := provider.counts()
	if jwksAfter <= jwksBefore {
		t.Fatalf("JWKS request count after unknown-kid login = %d, want greater than %d", jwksAfter, jwksBefore)
	}
}

func TestOIDCVerifiedEmailLinksExistingUserAndClosedModeRejectsJIT(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "closed")
	ctx := context.Background()
	email := "existing-oidc@example.test"
	user, err := store.CreateUser(ctx, stack.database.pool, store.User{
		ID: store.NewID(), Username: "existing-oidc-user", Email: &email,
		DisplayName: "Existing OIDC User", Status: "active",
	})
	if err != nil {
		t.Fatalf("create existing OIDC-link target: %v", err)
	}
	if err := store.SetEmailVerified(ctx, stack.database.pool, user.ID, time.Now().UTC()); err != nil {
		t.Fatalf("verify existing user's email: %v", err)
	}

	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "subject-existing", email, true, []string{"pwd"}, provider.currentKey(), nil)
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("verified-email link callback = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	linkedUserID, err := store.GetOIDCIdentity(ctx, stack.database.pool, provider.issuerURL(), "subject-existing")
	if err != nil || linkedUserID != user.ID {
		t.Fatalf("verified-email identity maps to %q, error = %v, want %q", linkedUserID, err, user.ID)
	}

	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "subject-unverified", email, false, []string{"pwd"}, provider.currentKey(), nil)
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("unverified-email link callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if _, err := store.GetOIDCIdentity(ctx, stack.database.pool, provider.issuerURL(), "subject-unverified"); !errors.Is(err, store.ErrNotFound) {
		t.Fatalf("unverified email created an OIDC identity, error = %v", err)
	}

	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "subject-closed", "closed-user@example.test", true, []string{"pwd"}, provider.currentKey(), nil)
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusForbidden || !strings.Contains(string(body), "registration_closed") {
		t.Fatalf("closed-mode JIT callback = %d %s, want registration_closed 403", status, body)
	}
}

func TestOIDCLinkRefusedForUnverifiedPendingInvitedAndErasedUsers(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "open")
	ctx := context.Background()
	tests := []struct {
		name            string
		status          string
		locallyVerified bool
		erased          bool
	}{
		{name: "active_unverified", status: "active"},
		{name: "pending", status: "pending", locallyVerified: true},
		{name: "invited", status: "invited", locallyVerified: true},
		{name: "erased", status: "disabled", locallyVerified: true, erased: true},
	}
	for _, tt := range tests {
		suffix := strings.ToLower(store.NewID())
		username := "oidc-link-refused-" + suffix
		email := username + "@example.test"
		createStatus := tt.status
		if tt.erased {
			createStatus = "active"
		}
		user, err := store.CreateUser(ctx, stack.database.pool, store.User{
			ID: store.NewID(), Username: username, Email: &email,
			DisplayName: "OIDC link-refusal test", Status: createStatus,
		})
		if err != nil {
			t.Fatalf("create %s OIDC link target: %v", tt.name, err)
		}
		if tt.locallyVerified {
			if err := store.SetEmailVerified(ctx, stack.database.pool, user.ID, time.Now().UTC()); err != nil {
				t.Fatalf("verify %s local email: %v", tt.name, err)
			}
		}
		if tt.erased {
			username = "deleted_" + user.ID
			email = username + "@deleted.invalid"
			if err := store.AnonymizeUser(ctx, stack.database.pool, user.ID, username, email); err != nil {
				t.Fatalf("anonymize %s OIDC link target: %v", tt.name, err)
			}
		}
		const preservedCredentialHash = "preserve-local-credential"
		if tt.name == "active_unverified" {
			if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
				UserID: user.ID, Kind: "password", Hash: preservedCredentialHash,
			}); err != nil {
				t.Fatalf("create local credential for unverified target: %v", err)
			}
		}

		state, nonce := beginOIDCLogin(t, stack)
		subject := "subject-" + tt.name + "-" + suffix
		code := provider.queueIDToken(t, nonce, subject, email, true, []string{"pwd"}, provider.currentKey(), nil)
		status, body := completeOIDCLogin(t, stack, state, code)
		if status != http.StatusForbidden || !strings.Contains(string(body), "oidc_link_refused") {
			t.Fatalf("%s OIDC link callback = %d %s, want oidc_link_refused 403", tt.name, status, body)
		}
		if _, err := store.GetOIDCIdentity(ctx, stack.database.pool, provider.issuerURL(), subject); !errors.Is(err, store.ErrNotFound) {
			t.Fatalf("%s email created an OIDC identity, error = %v", tt.name, err)
		}
		current, err := store.GetUser(ctx, stack.database.pool, user.ID)
		if err != nil {
			t.Fatalf("read %s OIDC link target: %v", tt.name, err)
		}
		if current.Status != tt.status || current.Username != username || (current.EmailVerifiedAt != nil) != tt.locallyVerified || current.Email == nil || *current.Email != email {
			t.Fatalf("%s OIDC link target changed during refused link: %+v", tt.name, current)
		}
		if tt.name == "active_unverified" {
			var credentialHash string
			if err := stack.database.pool.QueryRow(ctx, `SELECT hash FROM credentials WHERE user_id = $1 AND kind = 'password'`, user.ID).Scan(&credentialHash); err != nil {
				t.Fatalf("read preserved local credential: %v", err)
			}
			if credentialHash != preservedCredentialHash {
				t.Fatalf("local credential hash changed to %q", credentialHash)
			}
		}
	}
}

func TestOIDCApprovalModeCreatesPendingJITUser(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "approval")
	const email = "approval-oidc@example.test"
	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "subject-approval", email, true, []string{"pwd"}, provider.currentKey(), nil)
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusForbidden || !strings.Contains(string(body), "account_pending") {
		t.Fatalf("approval-mode OIDC callback = %d %s, want account_pending 403", status, body)
	}
	userID, err := store.GetOIDCIdentity(context.Background(), stack.database.pool, provider.issuerURL(), "subject-approval")
	if err != nil {
		t.Fatalf("read approval-mode OIDC identity: %v", err)
	}
	user, err := store.GetUser(context.Background(), stack.database.pool, userID)
	if err != nil {
		t.Fatalf("read approval-mode OIDC user: %v", err)
	}
	if user.Status != "pending" || user.EmailVerifiedAt == nil {
		t.Fatalf("approval-mode OIDC user = %+v, want pending with verified email", user)
	}
	if user.ID != userID {
		t.Fatalf("approval-mode OIDC identity maps to %q, want %q", userID, user.ID)
	}
}

func TestOIDCCallbackRejectsInvalidClaimsAndConsumesState(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "open")
	key := provider.currentKey()
	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "bad-nonce", "bad-nonce@example.test", true, []string{"pwd"}, key, map[string]any{"nonce": "different-nonce"})
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong-nonce callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	var failedOIDCActivities int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM login_activity
		WHERE method = 'oidc' AND result = 'failure'`).Scan(&failedOIDCActivities); err != nil {
		t.Fatalf("count failed OIDC login activity: %v", err)
	}
	if failedOIDCActivities != 1 {
		t.Fatalf("failed OIDC login activity count = %d, want 1", failedOIDCActivities)
	}
	_, exchangesBeforeReplay := provider.counts()
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("replayed OIDC state = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	_, exchangesAfterReplay := provider.counts()
	if exchangesAfterReplay != exchangesBeforeReplay {
		t.Fatalf("replayed state performed %d token exchanges, want unchanged count %d", exchangesAfterReplay, exchangesBeforeReplay)
	}

	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "bad-audience", "bad-audience@example.test", true, []string{"pwd"}, key, map[string]any{"aud": "another-client"})
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong-audience callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}

	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "expired-token", "expired-token@example.test", true, []string{"pwd"}, key, map[string]any{
		"exp": time.Now().UTC().Add(-time.Minute).Unix(),
	})
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("expired ID-token callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}

	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "wrong-issuer", "wrong-issuer@example.test", true, []string{"pwd"}, key, map[string]any{
		"iss": provider.issuerURL() + "/mismatch",
	})
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong-issuer callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}

	state, nonce = beginOIDCLogin(t, stack)
	untrustedKey := newMockOIDCSigningKey(t, key.kid)
	code = provider.queueIDToken(t, nonce, "bad-signature", "bad-signature@example.test", true, []string{"pwd"}, untrustedKey, nil)
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("bad-signature callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
}

func TestOIDCAlgorithmInferenceFromKeyWithoutJWKAlg(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "open")
	provider.setJWKAlgorithmOmitted(true)
	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "subject-alg-inference", "alg-inference@example.test", true, []string{"pwd"}, provider.currentKey(), nil)
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("ID token signed with allowed algorithm and alg-less JWK = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
}

func TestOIDCRejectsStaleAndFutureIDTokenTimes(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "open")
	tests := []struct {
		name      string
		overrides map[string]any
	}{
		{name: "iat_too_old", overrides: map[string]any{"iat": time.Now().UTC().Add(-11 * time.Minute).Unix()}},
		{name: "iat_too_far_in_future", overrides: map[string]any{"iat": time.Now().UTC().Add(31 * time.Second).Unix()}},
		{name: "nbf_too_far_in_future", overrides: map[string]any{"nbf": time.Now().UTC().Add(31 * time.Second).Unix()}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			state, nonce := beginOIDCLogin(t, stack)
			subject := "subject-invalid-time-" + tt.name
			email := tt.name + "@invalid-time.example.test"
			code := provider.queueIDToken(t, nonce, subject, email, true, []string{"pwd"}, provider.currentKey(), tt.overrides)
			status, body := completeOIDCLogin(t, stack, state, code)
			if status != http.StatusUnauthorized {
				t.Fatalf("%s ID-token callback = %d, want %d: %s", tt.name, status, http.StatusUnauthorized, body)
			}
		})
	}
}

func TestOIDCTokenEndpointRedirectIsNotFollowed(t *testing.T) {
	stack, provider := newOIDCIntegrationStack(t, "open")
	provider.setTokenRedirect(true)
	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "redirected-token", "redirected-token@example.test", true, []string{"pwd"}, provider.currentKey(), nil)
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusUnauthorized {
		t.Fatalf("redirecting token endpoint callback = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if requests := provider.redirectTargetRequestCount(); requests != 0 {
		t.Fatalf("token endpoint redirect target received %d requests, want 0", requests)
	}
}

func TestOIDCStepUpPreservesExternalEvidenceAndAcceptsUpstreamMFA(t *testing.T) {
	stack, provider := newOIDCIntegrationStackWithConfig(t, "open", func(cfg *config.Config) {
		cfg.OIDCTrustUpstreamMFA = true
	})
	key := provider.currentKey()
	state, nonce := beginOIDCLogin(t, stack)
	code := provider.queueIDToken(t, nonce, "subject-mfa", "mfa-user@example.test", true, []string{"pwd"}, key, nil)
	status, body := completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("initial OIDC login = %d, want %d: %s", status, http.StatusOK, body)
	}
	var initialPair tokenPair
	decodeResponse(t, body, &initialPair)
	assertTokenPair(t, initialPair)
	userID, err := store.GetOIDCIdentity(context.Background(), stack.database.pool, provider.issuerURL(), "subject-mfa")
	if err != nil {
		t.Fatalf("read OIDC MFA user's identity: %v", err)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/totp/enroll", nil, initialPair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("OIDC-authenticated TOTP enrollment = %d, want %d: %s", status, http.StatusOK, body)
	}
	var enrollment totpEnrollResponse
	decodeResponse(t, body, &enrollment)
	if enrollment.Secret == "" {
		t.Fatal("TOTP enrollment returned an empty secret")
	}
	if _, _, err := confirmTOTP(t, stack, enrollment.Secret, initialPair.AccessToken); err != nil {
		t.Fatalf("confirm TOTP for OIDC user: %v", err)
	}

	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "subject-mfa", "mfa-user@example.test", true, []string{"pwd"}, key, nil)
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("OIDC login requiring local TOTP = %d, want %d: %s", status, http.StatusOK, body)
	}
	var challenge mfaChallengeResponse
	decodeResponse(t, body, &challenge)
	if !challenge.MFARequired || challenge.MFAToken == "" {
		t.Fatalf("OIDC MFA challenge = %+v, want required token", challenge)
	}
	codeValue, err := currentTOTPCode(t, enrollment.Secret)
	if err != nil {
		t.Fatalf("generate OIDC user's TOTP: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login/mfa", map[string]string{
		"mfa_token": challenge.MFAToken,
		"code":      codeValue,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("OIDC local TOTP completion = %d, want %d: %s", status, http.StatusOK, body)
	}
	var steppedUpPair tokenPair
	decodeResponse(t, body, &steppedUpPair)
	assertTokenPair(t, steppedUpPair)
	steppedUpClaims := decodeAccessClaims(t, steppedUpPair.AccessToken)
	if len(steppedUpClaims.AMR) != 2 || steppedUpClaims.AMR[0] != "ext" || steppedUpClaims.AMR[1] != "otp" {
		t.Fatalf("post-TOTP AMR = %v, want [ext otp]", steppedUpClaims.AMR)
	}

	ctx := context.Background()
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "oidc-upstream-mfa"})
	if err != nil {
		t.Fatalf("create OIDC MFA role: %v", err)
	}
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: userID,
	}); err != nil {
		t.Fatalf("bind OIDC user to MFA role: %v", err)
	}
	if _, err := store.CreateMFAPolicy(ctx, stack.database.pool, store.MFAPolicy{
		Name: "OIDC upstream MFA", Priority: 100, SubjectKind: "role", SubjectID: role.ID, Required: true,
	}); err != nil {
		t.Fatalf("create required MFA policy for OIDC role: %v", err)
	}
	state, nonce = beginOIDCLogin(t, stack)
	code = provider.queueIDToken(t, nonce, "subject-mfa", "mfa-user@example.test", true, []string{"pwd", "otp"}, key, nil)
	status, body = completeOIDCLogin(t, stack, state, code)
	if status != http.StatusOK {
		t.Fatalf("upstream-MFA OIDC callback = %d, want %d: %s", status, http.StatusOK, body)
	}
	var upstreamPair tokenPair
	decodeResponse(t, body, &upstreamPair)
	assertTokenPair(t, upstreamPair)
	upstreamClaims := decodeAccessClaims(t, upstreamPair.AccessToken)
	if len(upstreamClaims.AMR) != 1 || upstreamClaims.AMR[0] != "ext" {
		t.Fatalf("upstream-MFA access-token AMR = %v, want [ext]", upstreamClaims.AMR)
	}
}

func TestOIDCUpstreamMFATrustIsOptInAndACRMatchesExactly(t *testing.T) {
	const allowedACR = "urn:teamusers:loa:mfa"
	tests := []struct {
		name          string
		trust         bool
		amr           []string
		acr           string
		wantChallenge bool
	}{
		{name: "default_trust_disabled", amr: []string{"pwd", "otp"}, wantChallenge: true},
		{name: "exact_acr_trusted", trust: true, amr: []string{"pwd"}, acr: allowedACR},
		{name: "near_match_acr_refused", trust: true, amr: []string{"pwd"}, acr: allowedACR + ":step-up", wantChallenge: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var stack *integrationStack
			var provider *mockOIDCProvider
			if tt.trust {
				stack, provider = newOIDCIntegrationStackWithConfig(t, "open", func(cfg *config.Config) {
					cfg.OIDCTrustUpstreamMFA = true
					cfg.OIDCMFAACRValues = []string{allowedACR}
				})
			} else {
				stack, provider = newOIDCIntegrationStack(t, "open")
			}
			ctx := context.Background()
			email := "oidc-upstream-" + tt.name + "@example.test"
			user, err := store.CreateUser(ctx, stack.database.pool, store.User{
				ID: store.NewID(), Username: "oidc-upstream-" + tt.name,
				Email: &email, DisplayName: "OIDC MFA test", Status: "active",
			})
			if err != nil {
				t.Fatalf("create OIDC MFA user: %v", err)
			}
			if err := store.SetEmailVerified(ctx, stack.database.pool, user.ID, time.Now().UTC()); err != nil {
				t.Fatalf("verify OIDC MFA user's email: %v", err)
			}
			subject := "subject-oidc-upstream-" + tt.name
			if _, err := store.CreateOIDCIdentity(ctx, stack.database.pool, user.ID, provider.issuerURL(), subject); err != nil {
				t.Fatalf("create OIDC MFA identity: %v", err)
			}
			if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
				UserID: user.ID, Kind: "totp", Hash: "unused-local-totp-seed",
			}); err != nil {
				t.Fatalf("create OIDC MFA credential: %v", err)
			}
			role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "oidc-upstream-mfa-" + tt.name})
			if err != nil {
				t.Fatalf("create OIDC MFA role: %v", err)
			}
			if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
				RoleID: role.ID, SubjectKind: "user", SubjectID: user.ID,
			}); err != nil {
				t.Fatalf("bind OIDC MFA user to role: %v", err)
			}
			if _, err := store.CreateMFAPolicy(ctx, stack.database.pool, store.MFAPolicy{
				Name: "OIDC upstream MFA " + tt.name, Priority: 100, SubjectKind: "role", SubjectID: role.ID, Required: true,
			}); err != nil {
				t.Fatalf("create OIDC MFA policy: %v", err)
			}

			state, nonce := beginOIDCLogin(t, stack)
			overrides := map[string]any{}
			if tt.acr != "" {
				overrides["acr"] = tt.acr
			}
			code := provider.queueIDToken(t, nonce, subject, email, true, tt.amr, provider.currentKey(), overrides)
			status, body := completeOIDCLogin(t, stack, state, code)
			if status != http.StatusOK {
				t.Fatalf("OIDC upstream MFA callback = %d, want %d: %s", status, http.StatusOK, body)
			}
			if tt.wantChallenge {
				var challenge mfaChallengeResponse
				decodeResponse(t, body, &challenge)
				if !challenge.MFARequired || challenge.MFAToken == "" {
					t.Fatalf("OIDC challenge = %+v, want local MFA challenge", challenge)
				}
				return
			}
			var pair tokenPair
			decodeResponse(t, body, &pair)
			assertTokenPair(t, pair)
		})
	}
}

func TestOIDCRoutesAreDisabledWithoutIssuer(t *testing.T) {
	stack := newIntegrationStack(t)
	for _, path := range []string{"/auth/oidc/begin", "/auth/oidc/callback?state=unused&code=unused"} {
		status, body := stack.jsonRequest(t, http.MethodGet, path, nil, "")
		if status != http.StatusNotFound || !strings.Contains(string(body), "oidc_not_configured") {
			t.Errorf("unconfigured OIDC route %s = %d %s, want oidc_not_configured 404", path, status, body)
		}
	}
}
