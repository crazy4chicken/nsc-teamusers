package httpapi

import "teamusers/internal/apidocs"

type docOIDCCallbackResponse struct {
	AccessToken           string   `json:"access_token,omitempty"`
	RefreshToken          string   `json:"refresh_token,omitempty"`
	TokenType             string   `json:"token_type,omitempty"`
	ExpiresIn             int64    `json:"expires_in,omitempty"`
	MFARequired           bool     `json:"mfa_required,omitempty"`
	MFAEnrollmentRequired bool     `json:"mfa_enrollment_required,omitempty"`
	MFAToken              string   `json:"mfa_token,omitempty"`
	MFAMethods            []string `json:"mfa_methods,omitempty"`
}

// DocOIDCOperations describes the external OpenID Connect login flow.
var DocOIDCOperations = []apidocs.Operation{
	{
		Method:      "GET",
		Path:        "/auth/oidc/begin",
		Tag:         "Authentication",
		Summary:     "Begin OIDC login",
		Description: "When OIDC is configured, redirects to the configured issuer with single-use state, nonce, and PKCE S256 challenge. The state and nonce digests, challenge, and verifier are stored server-side for five minutes. The endpoint sets a Secure, HttpOnly, SameSite=Lax __Host-oidc_state cookie containing the state digest, with Path=/ and no Domain; Secure is unconditional because TLS terminates at the trusted proxy. The endpoint is rate-limited and responds with an HTTP 302 Location header rather than a JSON body.",
		Response:    map[string]any{},
		Errors: []apidocs.ErrorDoc{
			docError(404, "oidc_not_configured", "OIDC Not Configured"),
			docRateLimited,
			docInternal,
		},
	},
	{
		Method:      "GET",
		Path:        "/auth/oidc/callback",
		Tag:         "Authentication",
		Summary:     "Complete OIDC login",
		Description: "Requires a matching state-digest cookie, consumes state once, and exchanges the authorization code with its PKCE verifier using a ten-second timeout. Verifies the signed ID token against cached issuer JWKS and validates issuer, audience, expiry, iat, nbf, and nonce; iat cannot be older than ten minutes or more than 30 seconds in the future, and nbf cannot be more than 30 seconds in the future. An unknown kid triggers a JWKS refresh. Email linking requires a locally verified email on a user that is not pending or invited; erased accounts are not linkable. Refused links return 403 oidc_link_refused. Returns a JSON token pair, or a JSON MFA step-up challenge when local MFA is required; it never redirects to a frontend.",
		Response:    docOIDCCallbackResponse{},
		ResponseExample: map[string]any{
			"access_token":  "signed-access-token",
			"refresh_token": "opaque-refresh-token",
			"token_type":    "Bearer",
			"expires_in":    600,
		},
		Errors: []apidocs.ErrorDoc{
			docUnauthorized,
			docError(403, "oidc_link_refused", "oidc_link_refused"),
			docError(403, "registration_closed", "registration_closed"),
			docError(403, "account_pending", "account_pending"),
			docError(403, "mfa_enrollment_denied", "mfa_enrollment_denied"),
			docError(404, "oidc_not_configured", "OIDC Not Configured"),
			docError(423, "account_locked", "account_locked"),
			docRateLimited,
			docInternal,
		},
	},
}

func init() {
	apidocs.RegisterOperations(DocOIDCOperations)
}
