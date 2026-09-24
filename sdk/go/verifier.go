package iam

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

const defaultIssuer = "teamusers"

// Option configures any SDK client. Options that do not apply to a specific
// constructor are ignored by that constructor.
type Option func(any)

// VerifierOption is the component-specific name for Option.
type VerifierOption = Option

// PermissionsOption is the component-specific name for Option.
type PermissionsOption = Option

// ClientOption is the component-specific name for Option.
type ClientOption = Option

// WithHTTPClient supplies the HTTP client used for JWKS and permission calls.
func WithHTTPClient(client *http.Client) Option {
	return func(target any) {
		switch value := target.(type) {
		case *Verifier:
			if client != nil {
				value.httpClient = client
			}
		case *PermissionsClient:
			if client != nil {
				value.httpClient = client
			}
		}
	}
}

// WithIssuer overrides the expected JWT issuer. The service default is
// "teamusers"; the JWKS URL is independent from the issuer claim.
func WithIssuer(issuer string) Option {
	return func(target any) {
		if value, ok := target.(*Verifier); ok {
			value.issuer = strings.TrimSpace(issuer)
		}
	}
}

// WithExpectedIssuer is an alias for WithIssuer.
func WithExpectedIssuer(issuer string) Option {
	return WithIssuer(issuer)
}

// WithJWKSMinRefreshInterval controls the minimum background refresh interval
// used by the jwx key cache.
func WithJWKSMinRefreshInterval(interval time.Duration) Option {
	return func(target any) {
		if value, ok := target.(*Verifier); ok && interval > 0 {
			value.jwksMinRefresh = interval
		}
	}
}

// WithServiceToken configures the bearer token used for service-only APIs.
func WithServiceToken(token string) Option {
	return func(target any) {
		if value, ok := target.(*PermissionsClient); ok {
			value.serviceToken = strings.TrimSpace(token)
		}
	}
}

// WithTokenSource configures a callback that supplies a current service token.
// It takes precedence over a static token.
func WithTokenSource(source func() (string, error)) Option {
	return func(target any) {
		if value, ok := target.(*PermissionsClient); ok {
			value.tokenSource = source
		}
	}
}

// WithPermissionsHTTPClient is an explicit alias for WithHTTPClient.
func WithPermissionsHTTPClient(client *http.Client) Option {
	return WithHTTPClient(client)
}

// WithPermissionsTTL configures the in-process permission entry TTL.
func WithPermissionsTTL(ttl time.Duration) Option {
	return func(target any) {
		if value, ok := target.(*PermissionsClient); ok && ttl >= 0 {
			value.ttl = ttl
		}
	}
}

// WithTTL is an alias for WithPermissionsTTL.
func WithTTL(ttl time.Duration) Option {
	return WithPermissionsTTL(ttl)
}

// WithRemoteOnly makes Client.Allow use the remote authorization endpoint
// rather than the local permission cache.
func WithRemoteOnly(remoteOnly bool) Option {
	return func(target any) {
		if value, ok := target.(*Client); ok {
			value.RemoteOnly = remoteOnly
		}
	}
}

// Verifier verifies EdDSA access tokens against a cached JWKS document.
type Verifier struct {
	issuerBaseURL  string
	jwksURL        string
	issuer         string
	httpClient     *http.Client
	jwksMinRefresh time.Duration
	cache          *jwk.Cache
	cacheContext   context.Context
	cacheCancel    context.CancelFunc
	registerError  error
	closeOnce      sync.Once
}

// NewVerifier constructs a lazy JWKS verifier. Construction does not require
// the issuer to be reachable; Verify returns the fetch error until the cache
// has obtained a usable JWKS document.
func NewVerifier(issuerBaseURL string, opts ...VerifierOption) *Verifier {
	base, jwksURL, err := normalizeIssuerURL(issuerBaseURL)
	cacheContext, cancel := context.WithCancel(context.Background())
	verifier := &Verifier{
		issuerBaseURL:  base,
		jwksURL:        jwksURL,
		issuer:         defaultIssuer,
		httpClient:     http.DefaultClient,
		jwksMinRefresh: time.Hour,
		cacheContext:   cacheContext,
		cacheCancel:    cancel,
		registerError:  err,
	}
	for _, opt := range opts {
		if opt != nil {
			opt(verifier)
		}
	}
	if verifier.issuer == "" {
		verifier.issuer = defaultIssuer
	}
	if err == nil {
		verifier.cache = jwk.NewCache(cacheContext)
		registerOpts := []jwk.RegisterOption{jwk.WithMinRefreshInterval(verifier.jwksMinRefresh)}
		if verifier.httpClient != nil {
			registerOpts = append(registerOpts, jwk.WithHTTPClient(verifier.httpClient))
		}
		if registerErr := verifier.cache.Register(jwksURL, registerOpts...); registerErr != nil {
			verifier.registerError = registerErr
		}
	}
	return verifier
}

// Close stops the jwx cache's background workers. It is safe to call more than
// once and is optional for process-lifetime verifiers.
func (v *Verifier) Close() error {
	if v == nil {
		return nil
	}
	v.closeOnce.Do(func() {
		if v.cacheCancel != nil {
			v.cacheCancel()
		}
	})
	return nil
}

// Verify validates an access token, including EdDSA signature, issuer,
// expiration, subject, kind, and permission version claims.
func (v *Verifier) Verify(ctx context.Context, raw string) (Claims, error) {
	if v == nil {
		return Claims{}, errors.New("nil verifier")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if v.registerError != nil {
		return Claims{}, fmt.Errorf("configure JWKS cache: %w", v.registerError)
	}
	if strings.TrimSpace(raw) == "" {
		return Claims{}, errors.New("access token is empty")
	}
	if v.cache == nil || v.jwksURL == "" {
		return Claims{}, errors.New("JWKS cache is unavailable")
	}
	set, err := v.cache.Get(ctx, v.jwksURL)
	if err != nil {
		return Claims{}, fmt.Errorf("fetch JWKS: %w", err)
	}

	if kid, ok := tokenKeyID(raw); ok {
		if _, present := set.LookupKeyID(kid); !present {
			refreshed, refreshErr := v.cache.Refresh(ctx, v.jwksURL)
			if refreshErr != nil {
				return Claims{}, fmt.Errorf("refresh JWKS for key %q: %w", kid, refreshErr)
			}
			set = refreshed
		}
	}

	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(set), jwt.WithValidate(true), jwt.WithIssuer(v.issuer))
	if err != nil {
		return Claims{}, fmt.Errorf("verify access token: %w", err)
	}
	if token.Issuer() != v.issuer {
		return Claims{}, errors.New("invalid access token issuer")
	}
	expiry := token.Expiration()
	if expiry.IsZero() || !expiry.After(time.Now()) {
		return Claims{}, errors.New("access token is expired")
	}
	subject := token.Subject()
	if subject == "" {
		return Claims{}, errors.New("access token subject is missing")
	}
	kind, ok := stringClaim(token, "kind")
	if !ok || (kind != "user" && kind != "service") {
		return Claims{}, errors.New("invalid access token kind")
	}
	permVer, ok := int64Claim(token, "perm_ver")
	if !ok || permVer < 0 {
		return Claims{}, errors.New("invalid access token perm_ver")
	}
	team := ""
	if value, present := token.Get("team"); present {
		var teamOK bool
		team, teamOK = value.(string)
		if !teamOK {
			return Claims{}, errors.New("invalid access token team")
		}
	}
	return Claims{Subject: subject, Team: team, Kind: kind, PermVer: permVer, Expiry: expiry}, nil
}

func normalizeIssuerURL(raw string) (string, string, error) {
	base := strings.TrimRight(strings.TrimSpace(raw), "/")
	if base == "" {
		return "", "", errors.New("issuer base URL is empty")
	}
	parsed, err := url.Parse(base)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		if err == nil {
			err = errors.New("URL must include scheme and host")
		}
		return base, "", fmt.Errorf("invalid issuer base URL: %w", err)
	}
	return base, base + "/.well-known/jwks.json", nil
}

func tokenKeyID(raw string) (string, bool) {
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		return "", false
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return "", false
	}
	var values struct {
		KeyID string `json:"kid"`
	}
	if err := json.Unmarshal(header, &values); err != nil || values.KeyID == "" {
		return "", false
	}
	return values.KeyID, true
}

func stringClaim(token jwt.Token, name string) (string, bool) {
	value, ok := token.Get(name)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func int64Claim(token jwt.Token, name string) (int64, bool) {
	value, ok := token.Get(name)
	if !ok {
		return 0, false
	}
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case int32:
		return int64(number), true
	case uint:
		return int64(number), uint64(number) <= uint64(^uint64(0)>>1)
	case uint64:
		return int64(number), number <= uint64(^uint64(0)>>1)
	case float64:
		return int64(number), number >= 0 && number == float64(int64(number))
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}
