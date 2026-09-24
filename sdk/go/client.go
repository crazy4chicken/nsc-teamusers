package iam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"
)

type claimsContextKey struct{}

// Client combines JWT verification with local permission checks and remote
// authorization fallback.
type Client struct {
	Verifier    *Verifier
	Permissions *PermissionsClient
	RemoteOnly  bool
}

// NewClient constructs a middleware client from a verifier and permission
// client. Either dependency may be nil; missing dependencies fail closed.
func NewClient(verifier *Verifier, permissions *PermissionsClient, opts ...ClientOption) *Client {
	client := &Client{Verifier: verifier, Permissions: permissions}
	for _, opt := range opts {
		if opt != nil {
			opt(client)
		}
	}
	return client
}

// WithVerifier configures a Client option with a verifier.
func WithVerifier(verifier *Verifier) Option {
	return func(target any) {
		if value, ok := target.(*Client); ok {
			value.Verifier = verifier
		}
	}
}

// WithPermissions configures a Client option with a permission client.
func WithPermissions(permissions *PermissionsClient) Option {
	return func(target any) {
		if value, ok := target.(*Client); ok {
			value.Permissions = permissions
		}
	}
}

// WithPermissionsClient is an alias for WithPermissions.
func WithPermissionsClient(permissions *PermissionsClient) Option {
	return WithPermissions(permissions)
}

// WithClaims returns a context carrying claims for downstream handlers.
func WithClaims(ctx context.Context, claims Claims) context.Context {
	if ctx == nil {
		ctx = context.Background()
	}
	return context.WithValue(ctx, claimsContextKey{}, claims)
}

// ClaimsFromContext retrieves verified claims installed by Middleware.
func ClaimsFromContext(ctx context.Context) (Claims, bool) {
	if ctx == nil {
		return Claims{}, false
	}
	switch value := ctx.Value(claimsContextKey{}).(type) {
	case Claims:
		return value, true
	case *Claims:
		if value != nil {
			return *value, true
		}
	}
	return Claims{}, false
}

// Middleware verifies a bearer access token and stores its Claims in the
// request context. Authentication failures are returned as a 401 decision.
func (c *Client) Middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if next == nil {
			writeDecision(w, http.StatusInternalServerError, "next handler is nil")
			return
		}
		if c == nil || c.Verifier == nil {
			writeUnauthorized(w, "authentication verifier unavailable")
			return
		}
		raw, ok := bearerToken(r.Header.Get("Authorization"))
		if !ok {
			writeUnauthorized(w, "bearer token is required")
			return
		}
		claims, err := c.Verifier.Verify(r.Context(), raw)
		if err != nil {
			writeUnauthorized(w, "authentication failed")
			return
		}
		next.ServeHTTP(w, r.WithContext(WithClaims(r.Context(), claims)))
	})
}

// Require returns middleware that authorizes one permission against the
// resource produced for each request.
func (c *Client) Require(permission string, resourceFrom func(*http.Request) Resource) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if next == nil {
				writeDecision(w, http.StatusInternalServerError, "next handler is nil")
				return
			}
			claims, ok := ClaimsFromContext(r.Context())
			if !ok {
				writeUnauthorized(w, "authentication is required")
				return
			}
			resource := Resource{}
			if resourceFrom != nil {
				resource = resourceFrom(r)
			}
			allowed, reason := c.Allow(r.Context(), claims, permission, resource)
			if !allowed {
				writeDecision(w, http.StatusForbidden, reason)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

// Allow evaluates a request against the local permission cache and falls back
// to the authoritative remote check when the cache cannot be fetched.
func (c *Client) Allow(ctx context.Context, claims Claims, permission string, resource Resource) (bool, string) {
	if ctx == nil {
		ctx = context.Background()
	}
	if claims.Subject == "" {
		return false, "subject is missing"
	}
	if !claims.Expiry.IsZero() && !claims.Expiry.After(time.Now()) {
		return false, "access token is expired"
	}
	if _, err := Parse(permission); err != nil {
		return false, "invalid permission"
	}
	if c == nil {
		return false, "authorization client unavailable"
	}
	if c.RemoteOnly {
		return c.remoteAllow(ctx, claims.Subject, permission, resource)
	}
	if c.Permissions == nil {
		return c.remoteAllow(ctx, claims.Subject, permission, resource)
	}
	entry, err := c.Permissions.Get(ctx, claims.Subject, claims.PermVer)
	if err != nil {
		return c.remoteAllow(ctx, claims.Subject, permission, resource)
	}
	if entry == nil {
		return false, "permission cache returned no entry"
	}
	if entry.PermVer != claims.PermVer {
		return false, "permission version mismatch"
	}
	requested, _ := Parse(permission)
	conditionRejected := false
	for _, grant := range entry.Grants {
		grantPermission := grant.permission
		if grantPermission.Resource == "" {
			var parseErr error
			grantPermission, parseErr = Parse(grant.Key)
			if parseErr != nil {
				continue
			}
		}
		if !Match(grantPermission, requested) {
			continue
		}
		if grant.Condition != nil && !grant.Condition.Eval(Context{
			Subject:  Subject{ID: claims.Subject, Kind: claims.Kind},
			Resource: resource,
			Request:  Request{Time: time.Now()},
		}) {
			conditionRejected = true
			continue
		}
		return true, "permission granted"
	}
	if conditionRejected {
		return false, "condition denied"
	}
	return false, "no matching grant"
}

// Check performs an explicit authoritative remote authorization check.
func (c *Client) Check(ctx context.Context, subject, permission string, resource Resource) (bool, string, error) {
	if c == nil || c.Permissions == nil {
		return false, "authorization client unavailable", errors.New("permission client is unavailable")
	}
	result, err := c.Permissions.Check(ctx, subject, permission, resource)
	if err != nil {
		return false, "authorization service unavailable", err
	}
	return result.Allow, result.Reason, nil
}

func (c *Client) remoteAllow(ctx context.Context, subject, permission string, resource Resource) (bool, string) {
	allowed, reason, err := c.Check(ctx, subject, permission, resource)
	if err != nil {
		return false, reason
	}
	return allowed, reason
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

type decisionResponse struct {
	Allow  bool   `json:"allow"`
	Reason string `json:"reason"`
}

func writeUnauthorized(w http.ResponseWriter, reason string) {
	w.Header().Set("WWW-Authenticate", `Bearer realm="teamusers"`)
	writeDecision(w, http.StatusUnauthorized, reason)
}

func writeDecision(w http.ResponseWriter, status int, reason string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(decisionResponse{Allow: false, Reason: reason})
}
