package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/mail"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/jwx/v2/jws"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"teamusers/internal/store"
)

const (
	oidcStateTTL         = 5 * time.Minute
	oidcDiscoveryTTL     = time.Hour
	oidcHTTPTimeout      = 10 * time.Second
	oidcMaxResponseBytes = 1 << 20
	oidcIDTokenClockSkew = 30 * time.Second
	oidcIDTokenMaxAge    = 10 * time.Minute
	oidcStateCookieName  = "__Host-oidc_state"
)

var (
	errOIDCInvalidAuthentication = errors.New("invalid OIDC authentication")
	errOIDCRegistrationClosed    = errors.New("OIDC registration is closed")
	errOIDCAccountLocked         = errors.New("OIDC account is locked")
	errOIDCAccountUnavailable    = errors.New("OIDC account is unavailable")
)

type oidcProvider struct {
	issuer       string
	clientID     string
	clientSecret string
	redirectURL  string
	httpClient   *http.Client
	// tokenHTTPClient rejects redirects because token requests carry the client secret.
	tokenHTTPClient *http.Client
	jwksCache    *jwk.Cache

	mu                   sync.Mutex
	metadata             oidcDiscovery
	metadataExpiresAt    time.Time
	registeredJWKSURLs   map[string]struct{}
}

type oidcDiscovery struct {
	Issuer                string `json:"issuer"`
	AuthorizationEndpoint string `json:"authorization_endpoint"`
	TokenEndpoint         string `json:"token_endpoint"`
	JWKSURI               string `json:"jwks_uri"`
}

type oidcTokenResponse struct {
	IDToken string `json:"id_token"`
}

type oidcJWSHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type oidcIdentityClaims struct {
	Issuer        string
	Subject       string
	Email         string
	EmailVerified bool
	Name          string
	AMR           []string
	ACR           string
}

type oidcLoginOutcome struct {
	user     store.User
	response tokenResponse
	challenge map[string]any
	problem  string
	success  bool
}

func (s *Service) currentOIDCProvider() *oidcProvider {
	s.oidcMu.Lock()
	defer s.oidcMu.Unlock()
	if s.oidc == nil {
		s.oidc = &oidcProvider{
			issuer:       strings.TrimSpace(s.cfg.OIDCIssuer),
			clientID:     strings.TrimSpace(s.cfg.OIDCClientID),
			clientSecret: s.cfg.OIDCClientSecret,
			redirectURL:  strings.TrimSpace(s.cfg.OIDCRedirectURL),
			httpClient:   &http.Client{Timeout: oidcHTTPTimeout},
			tokenHTTPClient: &http.Client{
				Timeout: oidcHTTPTimeout,
				CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
					return http.ErrUseLastResponse
				},
			},
			jwksCache:    jwk.NewCache(context.Background()),
			registeredJWKSURLs: make(map[string]struct{}),
		}
	}
	return s.oidc
}

func (s *Service) oidcBegin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	if strings.TrimSpace(s.cfg.OIDCIssuer) == "" {
		writeAuthProblem(w, r, http.StatusNotFound, "oidc_not_configured")
		return
	}

	provider := s.currentOIDCProvider()
	discovery, err := provider.discover(r.Context())
	if err != nil {
		writeInternal(w, r)
		return
	}
	state, err := newOIDCSecret()
	if err != nil {
		writeInternal(w, r)
		return
	}
	nonce, err := newOIDCSecret()
	if err != nil {
		writeInternal(w, r)
		return
	}
	codeVerifier, err := newOIDCSecret()
	if err != nil {
		writeInternal(w, r)
		return
	}
	now := s.now().UTC()
	stateHash := hashVerificationToken(state)
	nonceHash := hashVerificationToken(nonce)
	codeChallenge := oidcCodeChallengeS256(codeVerifier)
	if err := store.CreateOIDCLoginState(
		r.Context(), s.q, stateHash, nonceHash,
		codeChallenge, codeVerifier, now.Add(oidcStateTTL), now,
	); err != nil {
		writeInternal(w, r)
		return
	}

	authorizationURL, err := url.Parse(discovery.AuthorizationEndpoint)
	if err != nil {
		writeInternal(w, r)
		return
	}
	query := authorizationURL.Query()
	query.Set("response_type", "code")
	query.Set("client_id", provider.clientID)
	query.Set("redirect_uri", provider.redirectURL)
	query.Set("scope", "openid email profile")
	query.Set("state", state)
	query.Set("nonce", nonce)
	query.Set("code_challenge", codeChallenge)
	query.Set("code_challenge_method", "S256")
	authorizationURL.RawQuery = query.Encode()

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	// Secure is unconditional because the production TLS boundary is the trusted proxy.
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookieName, Value: stateHash, Path: "/",
		Expires: now.Add(oidcStateTTL), MaxAge: int(oidcStateTTL / time.Second),
		HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
	http.Redirect(w, r, authorizationURL.String(), http.StatusFound)
}

func (s *Service) oidcCallback(w http.ResponseWriter, r *http.Request) {
	if strings.TrimSpace(s.cfg.OIDCIssuer) == "" {
		writeAuthProblem(w, r, http.StatusNotFound, "oidc_not_configured")
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	w.Header().Set("Referrer-Policy", "no-referrer")
	var activityUser store.User
	attemptedEmail := ""
	activityRecorded := false
	defer func() {
		if !activityRecorded {
			s.recordLoginActivityFromRequest(r.Context(), s.q, r, activityUser, attemptedEmail, "oidc", "failure")
		}
	}()

	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}

	query := r.URL.Query()
	states := query["state"]
	if len(states) != 1 || states[0] == "" {
		writeUnauthorized(w, r)
		return
	}
	state := states[0]
	if !oidcStateCookieMatches(r, state) {
		writeUnauthorized(w, r)
		return
	}
	nonceHash, codeChallenge, codeVerifier, err := store.ConsumeOIDCLoginState(r.Context(), s.q, hashVerificationToken(state), s.now())
	if errors.Is(err, store.ErrNotFound) {
		clearOIDCStateCookie(w)
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	clearOIDCStateCookie(w)
	if codeChallenge == "" || codeVerifier == "" ||
		subtle.ConstantTimeCompare([]byte(codeChallenge), []byte(oidcCodeChallengeS256(codeVerifier))) != 1 {
		writeUnauthorized(w, r)
		return
	}
	codes := query["code"]
	if query.Get("error") != "" || len(codes) != 1 || codes[0] == "" {
		writeUnauthorized(w, r)
		return
	}

	provider := s.currentOIDCProvider()
	discovery, err := provider.discover(r.Context())
	if err != nil {
		writeInternal(w, r)
		return
	}
	idToken, err := provider.exchangeCode(r.Context(), discovery, codes[0], codeVerifier)
	if errors.Is(err, errOIDCInvalidAuthentication) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	claims, err := provider.verifyIDToken(r.Context(), discovery, idToken, nonceHash, s.now())
	if errors.Is(err, errOIDCInvalidAuthentication) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	attemptedEmail = claims.Email

	outcome, err := s.completeOIDCLogin(r.Context(), r, claims)
	activityUser = outcome.user
	if errors.Is(err, errOIDCRegistrationClosed) {
		writeAuthProblem(w, r, http.StatusForbidden, "registration_closed")
		return
	}
	if errors.Is(err, store.ErrOIDCLinkRefused) {
		writeAuthProblem(w, r, http.StatusForbidden, "oidc_link_refused")
		return
	}
	if errors.Is(err, errOIDCAccountLocked) {
		s.auditAuth(r.Context(), s.q, "auth.login.locked", outcome.user, outcome.user.ID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	if errors.Is(err, errOIDCAccountUnavailable) || errors.Is(err, errOIDCInvalidAuthentication) || errors.Is(err, store.ErrOIDCEmailAmbiguous) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	if outcome.problem == "account_pending" {
		writeAuthProblem(w, r, http.StatusForbidden, "account_pending")
		return
	}
	if outcome.problem == "mfa_enrollment_denied" {
		writeAuthProblem(w, r, http.StatusForbidden, "mfa_enrollment_denied")
		return
	}
	if !outcome.success {
		writeInternal(w, r)
		return
	}

	activityRecorded = true
	if outcome.challenge != nil {
		writeJSON(w, http.StatusOK, outcome.challenge)
		return
	}
	writeJSON(w, http.StatusOK, outcome.response)
}

func (s *Service) completeOIDCLogin(ctx context.Context, r *http.Request, claims oidcIdentityClaims) (oidcLoginOutcome, error) {
	var outcome oidcLoginOutcome
	lockedEmail := ""
	if claims.EmailVerified && validOIDCEmail(claims.Email) {
		lockedEmail = strings.ToLower(claims.Email)
	}
	err := store.WithAdminTx(ctx, s.q, func(txctx context.Context, tx store.Tx) error {
		if err := store.LockOIDCLogin(txctx, tx, claims.Issuer, claims.Subject, lockedEmail); err != nil {
			return err
		}

		identityUserID, err := store.GetOIDCIdentity(txctx, tx, claims.Issuer, claims.Subject)
		identityExists := err == nil
		if err != nil && !errors.Is(err, store.ErrNotFound) {
			return err
		}

		var user store.User
		if identityExists {
			user, err = store.GetUser(txctx, tx, identityUserID)
			if err != nil {
				return err
			}
		} else {
			if !claims.EmailVerified || !validOIDCEmail(claims.Email) {
				return errOIDCInvalidAuthentication
			}
			user, err = store.GetOIDCUserByEmail(txctx, tx, claims.Email)
			if errors.Is(err, pgx.ErrNoRows) {
				mode := s.registrationMode()
				if mode == "closed" {
					return errOIDCRegistrationClosed
				}
				userID := store.NewID()
				username := "oidc-" + strings.ToLower(userID)
				email := claims.Email
				status := "pending"
				if mode == "open" {
					status = "active"
				}
				user, err = store.CreateUser(txctx, tx, store.User{
					ID: userID, Username: username, Email: &email,
					DisplayName: strings.TrimSpace(claims.Name), Status: status,
				})
				if err != nil {
					return err
				}
				if err := store.SetEmailVerified(txctx, tx, user.ID, s.now()); err != nil {
					return err
				}
				user, err = store.GetUser(txctx, tx, user.ID)
				if err != nil {
					return err
				}
				if err := store.AppendUserLifecycleEvent(txctx, tx, "user.created", nil, &user); err != nil {
					return err
				}
			} else if errors.Is(err, store.ErrOIDCEmailAmbiguous) {
				return errOIDCInvalidAuthentication
			} else if err != nil {
				return err
			}
		}

		outcome.user = user
		if user.Status == "disabled" {
			return errOIDCAccountUnavailable
		}
		if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
			return errOIDCAccountLocked
		}

		if !identityExists {
			linkedID, err := store.CreateOIDCIdentity(txctx, tx, user.ID, claims.Issuer, claims.Subject)
			if err != nil {
				return err
			}
			if linkedID != user.ID {
				user, err = store.GetUser(txctx, tx, linkedID)
				if err != nil {
					return err
				}
				outcome.user = user
			}
			if err := s.appendAuthAudit(txctx, tx, "auth.oidc.identity_linked", user.ID, user.ID); err != nil {
				return err
			}
		}

		if claims.EmailVerified && validOIDCEmail(claims.Email) && user.Email != nil && strings.EqualFold(*user.Email, claims.Email) {
			before := user
			changed := false
			if user.EmailVerifiedAt == nil {
				if err := store.SetEmailVerified(txctx, tx, user.ID, s.now()); err != nil {
					return err
				}
				changed = true
			}
			if user.Status == "pending" && s.registrationMode() == "open" {
				if _, err := tx.Exec(txctx, `
					UPDATE users SET status = 'active', updated_at = now()
					WHERE id = $1 AND status = 'pending'`, user.ID); err != nil {
					return err
				}
				changed = true
			}
			if changed {
				user, err = store.GetUser(txctx, tx, user.ID)
				if err != nil {
					return err
				}
				if err := store.AppendUserLifecycleEvent(txctx, tx, "user.updated", &before, &user); err != nil {
					return err
				}
				outcome.user = user
			}
		}

		if user.Status != "active" {
			if user.Status == "pending" || user.Status == "invited" {
				outcome.problem = "account_pending"
				outcome.user = user
				return nil
			}
			return errOIDCAccountUnavailable
		}

		policy, err := store.ResolveMFAPolicy(txctx, tx, user.ID, s.now())
		if err != nil {
			return err
		}
		required := policy.ID != "" && policy.Required
		_, credentialErr := store.GetCredential(txctx, tx, user.ID, "totp")
		hasTOTP := credentialErr == nil
		if credentialErr != nil && !errors.Is(credentialErr, pgx.ErrNoRows) {
			return credentialErr
		}

		primaryAuthTime := s.now().Unix()
		metadata := sessionMetadataFor(r, "user")
		metadata.AuthTime = primaryAuthTime
		metadata.AMR = []string{"ext"}
		upstreamMFA := s.cfg.OIDCTrustUpstreamMFA && oidcClaimsIndicateMFA(claims.AMR, claims.ACR, s.cfg.OIDCMFAACRValues)
		if hasTOTP && !upstreamMFA {
			mfaToken, err := s.signMFAToken(user.ID, primaryAuthTime, []string{"ext"})
			if err != nil {
				return err
			}
			outcome.challenge = map[string]any{
				"mfa_required": true, "mfa_token": mfaToken, "mfa_methods": []string{"otp"},
			}
			s.recordLoginActivityFromMetadata(txctx, tx, user, "oidc", "success", metadata)
			outcome.success = true
			return nil
		}
		if required && !upstreamMFA {
			if policy.DenyUnenrolled {
				outcome.problem = "mfa_enrollment_denied"
				return nil
			}
			enrollmentToken, err := s.signMFAEnrollmentToken(user.ID, primaryAuthTime, []string{"ext"})
			if err != nil {
				return err
			}
			outcome.challenge = map[string]any{
				"mfa_enrollment_required": true,
				"mfa_token":               enrollmentToken,
				"mfa_methods":             []string{"otp"},
			}
			s.recordLoginActivityFromMetadata(txctx, tx, user, "oidc", "success", metadata)
			outcome.success = true
			return nil
		}

		if err := store.ResetFailedLogins(txctx, tx, user.ID); err != nil {
			return err
		}
		outcome.response, err = s.issuePair(txctx, tx, user, "user", "", time.Time{}, metadata)
		if err != nil {
			return err
		}
		if err := s.appendAuthAudit(txctx, tx, "auth.login.succeeded", user.ID, user.ID); err != nil {
			return err
		}
		s.recordLoginActivityFromMetadata(txctx, tx, user, "oidc", "success", metadata)
		outcome.user = user
		outcome.success = true
		return nil
	})
	return outcome, err
}

func (p *oidcProvider) discover(ctx context.Context) (oidcDiscovery, error) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.metadata.Issuer != "" && time.Now().Before(p.metadataExpiresAt) {
		return p.metadata, nil
	}

	issuerURL, err := url.Parse(p.issuer)
	if err != nil {
		return oidcDiscovery{}, err
	}
	issuerURL.Path = strings.TrimRight(issuerURL.Path, "/") + "/.well-known/openid-configuration"
	issuerURL.RawPath = ""
	metadataURL := issuerURL.String()
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, metadataURL, nil)
	if err != nil {
		return oidcDiscovery{}, err
	}
	response, err := p.httpClient.Do(request)
	if err != nil {
		return oidcDiscovery{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return oidcDiscovery{}, fmt.Errorf("OIDC discovery returned HTTP %d", response.StatusCode)
	}
	var metadata oidcDiscovery
	if err := decodeOIDCJSON(response, &metadata); err != nil {
		return oidcDiscovery{}, err
	}
	if metadata.Issuer != p.issuer || validateOIDCEndpoint("authorization endpoint", metadata.AuthorizationEndpoint, issuerURL.Scheme) != nil ||
		validateOIDCEndpoint("token endpoint", metadata.TokenEndpoint, issuerURL.Scheme) != nil ||
		validateOIDCEndpoint("JWKS URI", metadata.JWKSURI, issuerURL.Scheme) != nil {
		return oidcDiscovery{}, errors.New("OIDC discovery metadata is invalid")
	}
	if _, ok := p.registeredJWKSURLs[metadata.JWKSURI]; !ok {
		if err := p.jwksCache.Register(metadata.JWKSURI, jwk.WithMinRefreshInterval(time.Hour), jwk.WithHTTPClient(p.httpClient)); err != nil {
			return oidcDiscovery{}, err
		}
		p.registeredJWKSURLs[metadata.JWKSURI] = struct{}{}
	}
	p.metadata = metadata
	p.metadataExpiresAt = time.Now().Add(oidcDiscoveryTTL)
	return metadata, nil
}

func (p *oidcProvider) exchangeCode(ctx context.Context, discovery oidcDiscovery, code, codeVerifier string) (string, error) {
	form := url.Values{
		"grant_type":    {"authorization_code"},
		"code":          {code},
		"redirect_uri":  {p.redirectURL},
		"code_verifier": {codeVerifier},
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, discovery.TokenEndpoint, strings.NewReader(form.Encode()))
	if err != nil {
		return "", err
	}
	request.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	request.SetBasicAuth(p.clientID, p.clientSecret)
	response, err := p.tokenHTTPClient.Do(request)
	if err != nil {
		return "", err
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		if response.StatusCode < http.StatusInternalServerError {
			return "", errOIDCInvalidAuthentication
		}
		return "", fmt.Errorf("OIDC token endpoint returned HTTP %d", response.StatusCode)
	}
	var tokenResponse oidcTokenResponse
	if err := decodeOIDCJSON(response, &tokenResponse); err != nil {
		return "", err
	}
	if tokenResponse.IDToken == "" {
		return "", errOIDCInvalidAuthentication
	}
	return tokenResponse.IDToken, nil
}

func (p *oidcProvider) verifyIDToken(ctx context.Context, discovery oidcDiscovery, raw, expectedNonceHash string, now time.Time) (oidcIdentityClaims, error) {
	header, err := parseOIDCJWSHeader(raw)
	if err != nil || !allowedOIDCSigningAlgorithm(header.Algorithm) {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}
	keySet, err := p.jwksCache.Get(ctx, discovery.JWKSURI)
	if err != nil {
		return oidcIdentityClaims{}, err
	}
	if header.KeyID != "" {
		if _, ok := keySet.LookupKeyID(header.KeyID); !ok {
			keySet, err = p.jwksCache.Refresh(ctx, discovery.JWKSURI)
			if err != nil {
				return oidcIdentityClaims{}, err
			}
			if _, ok := keySet.LookupKeyID(header.KeyID); !ok {
				return oidcIdentityClaims{}, errOIDCInvalidAuthentication
			}
		}
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(keySet, jws.WithInferAlgorithmFromKey(true)), jwt.WithValidate(false))
	if err != nil {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}
	if token.Issuer() != p.issuer || token.Subject() == "" || token.Expiration().IsZero() || !token.Expiration().After(now) {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}
	issuedAt := token.IssuedAt()
	if issuedAt.IsZero() || issuedAt.Before(now.Add(-oidcIDTokenMaxAge)) || issuedAt.After(now.Add(oidcIDTokenClockSkew)) {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}
	if _, present := token.Get("nbf"); present {
		notBefore := token.NotBefore()
		if notBefore.IsZero() || notBefore.After(now.Add(oidcIDTokenClockSkew)) {
			return oidcIdentityClaims{}, errOIDCInvalidAuthentication
		}
	}
	audiences := token.Audience()
	audienceMatches := false
	for _, audience := range audiences {
		if audience == p.clientID {
			audienceMatches = true
			break
		}
	}
	if !audienceMatches {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}
	if authorizedParty, present := token.Get("azp"); present {
		value, ok := authorizedParty.(string)
		if !ok || value != p.clientID {
			return oidcIdentityClaims{}, errOIDCInvalidAuthentication
		}
	} else if len(audiences) > 1 {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}
	nonce, ok := stringClaim(token, "nonce")
	if !ok || subtle.ConstantTimeCompare([]byte(hashVerificationToken(nonce)), []byte(expectedNonceHash)) != 1 {
		return oidcIdentityClaims{}, errOIDCInvalidAuthentication
	}

	email, _ := stringClaim(token, "email")
	name, _ := stringClaim(token, "name")
	acr, _ := stringClaim(token, "acr")
	amr, _ := stringSliceClaim(token, "amr")
	emailVerifiedValue, _ := token.Get("email_verified")
	emailVerified, _ := emailVerifiedValue.(bool)
	return oidcIdentityClaims{
		Issuer: token.Issuer(), Subject: token.Subject(), Email: email,
		EmailVerified: emailVerified, Name: name, AMR: amr, ACR: acr,
	}, nil
}

func decodeOIDCJSON(response *http.Response, destination any) error {
	body, err := io.ReadAll(io.LimitReader(response.Body, oidcMaxResponseBytes+1))
	if err != nil {
		return err
	}
	if len(body) > oidcMaxResponseBytes {
		return errors.New("OIDC response is too large")
	}
	if err := json.Unmarshal(body, destination); err != nil {
		return errors.New("OIDC response is invalid JSON")
	}
	return nil
}

func validateOIDCEndpoint(name, raw, issuerScheme string) error {
	endpoint, err := url.Parse(raw)
	if err != nil || !endpoint.IsAbs() || endpoint.Hostname() == "" ||
		(endpoint.Scheme != "http" && endpoint.Scheme != "https") || endpoint.User != nil || endpoint.Fragment != "" {
		return fmt.Errorf("invalid OIDC %s", name)
	}
	if issuerScheme == "https" && endpoint.Scheme != "https" {
		return fmt.Errorf("OIDC %s must use HTTPS", name)
	}
	return nil
}

func newOIDCSecret() (string, error) {
	var data [32]byte
	if _, err := rand.Read(data[:]); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(data[:]), nil
}


func oidcCodeChallengeS256(verifier string) string {
	digest := sha256.Sum256([]byte(verifier))
	return base64.RawURLEncoding.EncodeToString(digest[:])
}

func oidcStateCookieMatches(r *http.Request, state string) bool {
	expected := hashVerificationToken(state)
	var value string
	found := false
	for _, cookie := range r.Cookies() {
		if cookie.Name == oidcStateCookieName {
			if found {
				return false
			}
			found = true
			value = cookie.Value
		}
	}
	return found && subtle.ConstantTimeCompare([]byte(value), []byte(expected)) == 1
}

func clearOIDCStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name: oidcStateCookieName, Value: "", Path: "/", MaxAge: -1,
		Expires: time.Unix(1, 0), HttpOnly: true, Secure: true, SameSite: http.SameSiteLaxMode,
	})
}
func parseOIDCJWSHeader(raw string) (oidcJWSHeader, error) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return oidcJWSHeader{}, errors.New("invalid JWS compact serialization")
	}
	encoded, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return oidcJWSHeader{}, err
	}
	var header oidcJWSHeader
	if err := json.Unmarshal(encoded, &header); err != nil || header.Algorithm == "" {
		return oidcJWSHeader{}, errors.New("invalid JWS header")
	}
	return header, nil
}

func allowedOIDCSigningAlgorithm(algorithm string) bool {
	switch algorithm {
	case "RS256", "RS384", "RS512", "PS256", "PS384", "PS512", "ES256", "ES384", "ES512", "EdDSA":
		return true
	default:
		return false
	}
}

func validOIDCEmail(email string) bool {
	if email == "" || len(email) > 320 || strings.TrimSpace(email) != email {
		return false
	}
	parsed, err := mail.ParseAddress(email)
	return err == nil && parsed.Address == email
}

func oidcClaimsIndicateMFA(amr []string, acr string, acrValues []string) bool {
	for _, method := range amr {
		method = strings.TrimSpace(method)
		switch {
		case strings.EqualFold(method, "mfa"), strings.EqualFold(method, "multifactor"),
			strings.EqualFold(method, "multi_factor"), strings.EqualFold(method, "multi-factor"),
			strings.EqualFold(method, "2fa"), strings.EqualFold(method, "two_factor"),
			strings.EqualFold(method, "two-factor"):
			return true
		}
	}
	for _, value := range acrValues {
		if acr == value {
			return true
		}
	}

	const (
		knowledgeFactor uint8 = 1 << iota
		possessionFactor
		inherenceFactor
	)
	var factors uint8
	for _, method := range amr {
		method = strings.TrimSpace(method)
		switch {
		case strings.EqualFold(method, "pwd"), strings.EqualFold(method, "pin"):
			factors |= knowledgeFactor
		case strings.EqualFold(method, "otp"), strings.EqualFold(method, "sms"),
			strings.EqualFold(method, "hwk"), strings.EqualFold(method, "swk"),
			strings.EqualFold(method, "fido"), strings.EqualFold(method, "webauthn"):
			factors |= possessionFactor
		case strings.EqualFold(method, "fpt"), strings.EqualFold(method, "face"),
			strings.EqualFold(method, "iris"), strings.EqualFold(method, "retina"),
			strings.EqualFold(method, "vbm"):
			factors |= inherenceFactor
		}
	}
	return factors&(factors-1) != 0
}
