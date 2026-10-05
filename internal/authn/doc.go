package authn

import (
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"

"github.com/crazy4chicken/nsc-teamusers/apidocs/go"

"teamusers/internal/apidocsgen"
"teamusers/internal/audit"
"teamusers/internal/authz"
"teamusers/internal/config"
"teamusers/internal/httpapi"
"teamusers/internal/store"
)

type loginResponse struct {
	AccessToken           string   `json:"access_token,omitempty"`
	RefreshToken          string   `json:"refresh_token,omitempty"`
	TokenType             string   `json:"token_type,omitempty"`
	ExpiresIn             int64    `json:"expires_in,omitempty"`
	MFARequired           bool     `json:"mfa_required,omitempty"`
	MFAEnrollmentRequired bool     `json:"mfa_enrollment_required,omitempty"`
	MFAToken              string   `json:"mfa_token,omitempty"`
	MFAMethods            []string `json:"mfa_methods,omitempty"`
}

// DocOperations is the authentication route contract used by the OpenAPI
// generator.
var DocOperations = []apidocs.Operation{
	{
		Method:      "GET",
		Path:        "/.well-known/jwks.json",
		Tag:         "Authentication",
		Summary:     "Fetch public signing keys",
		Description: "Use this public endpoint to validate teamusers EdDSA JWT signatures locally. API gateways and services call it and cache the returned key set by kid.",
		Response:    map[string]any{},
		ResponseExample: map[string]any{
			"keys": []any{
				map[string]any{
					"kid": "01J8Z3KEY00000000000000001",
					"kty": "OKP",
					"crv": "Ed25519",
					"alg": "EdDSA",
					"use": "sig",
					"x":   "11qYAYL9f3rK3z7Z4Yj6d8bYJQ4mC3bX2h0qk8mVqB8",
				},
			},
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 500, Code: "jwks unavailable", Title: "Signing key set could not be encoded"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/register",
		Tag:         "Authentication",
		Summary:     "Register a user",
		Description: "Use for public self-registration when registration mode is open or approval. A web or mobile client submits the profile and password; the service creates a pending account and sends an email verification notification. Closed mode rejects registration.",
		Request:     registerRequest{},
		RequestExample: map[string]any{
			"username":     "alice",
			"email":        "alice@example.test",
			"password":     "AtLeastTwelve1",
			"display_name": "Alice Example",
		},
		Response:        map[string]string{},
		ResponseExample: map[string]any{"id": "01J8Z3USER000000000000001", "status": "pending"},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 403, Code: "registration_closed", Title: "registration_closed"},
			{Status: 422, Code: "weak_password", Title: "weak_password"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/verify-email",
		Tag:         "Authentication",
		Summary:     "Verify an email address",
		Description: "Use from the link or token delivered by the notification service after registration. It marks the account verified and, in open mode, activates it; approval mode still requires administrator approval.",
		Request:     verifyEmailRequest{},
		RequestExample: map[string]any{
			"token": "verification-token-from-email",
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "invalid_token", Title: "invalid_token"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/login",
		Tag:         "Authentication",
		Summary:     "Sign in with a password",
		Description: "Use when an end user needs an access and refresh token pair. Administrator-provisioned passwords instead return 403 password_change_required with a ten-minute change_token accepted only by POST /me/password; that endpoint still verifies the current password. Accounts with TOTP enabled or an effective required-MFA policy receive an initial MFA challenge, or a restricted MFA-enrollment token when required TOTP is not enrolled. Complete this login challenge at POST /auth/login/mfa; it is distinct from authenticated MFA-only step-up. Access tokens carry auth_time for primary authentication and may carry step_up_time only after POST /auth/step-up/complete; refresh preserves both.",
		Request:     loginRequest{},
		RequestExample: map[string]any{
			"username": "alice",
			"password": "AtLeastTwelve1",
		},
		Response: loginResponse{},
		ResponseExample: map[string]any{
			"mfa_required": true,
			"mfa_token":    "eyJhbGciOiJFZERTQSIs...",
			"mfa_methods":  []string{"otp"},
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 403, Code: "account_pending", Title: "account_pending"},
			{Status: 403, Code: "password_change_required", Title: "password_change_required"},
			{Status: 403, Code: "mfa_enrollment_denied", Title: "mfa_enrollment_denied"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/login/mfa",
		Tag:         "Authentication",
		Summary:     "Complete MFA login",
		Description: "Use after password or passkey login returns mfa_required. Submit the short-lived MFA token and either a current TOTP code or one unused backup code. This completes initial login MFA, not MFA-only step-up; success returns the normal token pair with the primary-auth auth_time unchanged and additive amr claims.",
		Request:     mfaLoginRequest{},
		RequestExample: map[string]any{
			"mfa_token": "eyJhbGciOiJFZERTQSIs...",
			"code":      "123456",
		},
		Response: tokenResponse{},
		ResponseExample: map[string]any{
			"access_token":  "eyJhbGciOiJFZERTQSIs...",
			"refresh_token": "refresh-token-opaque",
			"token_type":    "Bearer",
			"expires_in":    600,
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:          "POST",
		Path:            "/auth/login/mfa/enroll/begin",
		Tag:             "Authentication",
		Summary:         "Begin required MFA enrollment",
		Description:     "Use with the restricted mfa_token returned as mfa_enrollment_required when required TOTP is not enrolled. It authorizes only initial-login enrollment and returns a pending TOTP secret; it is not an access token. MFA-only step-up never enrolls a factor.",
		Request:         mfaEnrollmentRequest{},
		RequestExample:  map[string]any{"mfa_token": "eyJhbGciOiJFZERTQSIs..."},
		Response:        totpResponse{},
		ResponseExample: map[string]any{"secret": "JBSWY3DPEHPK3PXP", "otpauth_url": "otpauth://totp/teamusers:alice?secret=JBSWY3DPEHPK3PXP&issuer=teamusers"},
		Errors:          []apidocs.ErrorDoc{{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"}, {Status: 401, Code: "authentication failed", Title: "Unauthorized"}, {Status: 409, Code: "totp_already_enabled", Title: "totp_already_enabled"}, {Status: 423, Code: "account_locked", Title: "account_locked"}, {Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"}, {Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"}},
	},
	{
		Method:          "POST",
		Path:            "/auth/login/mfa/enroll/complete",
		Tag:             "Authentication",
		Summary:         "Complete required MFA enrollment",
		Description:     "Use after beginning required TOTP enrollment with the same restricted mfa_token. A valid code activates TOTP and returns backup codes with a full token pair whose amr includes otp and whose auth_time remains the primary authentication time. This initial enrollment flow is distinct from MFA-only step-up.",
		Request:         mfaEnrollmentRequest{},
		RequestExample:  map[string]any{"mfa_token": "eyJhbGciOiJFZERTQSIs...", "code": "123456"},
		Response:        mfaEnrollmentCompleteResponse{},
		ResponseExample: map[string]any{"access_token": "eyJhbGciOiJFZERTQSIs...", "refresh_token": "refresh-token-opaque", "token_type": "Bearer", "expires_in": 600, "backup_codes": []string{"abcd1234efgh5678"}},
		Errors:          []apidocs.ErrorDoc{{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"}, {Status: 401, Code: "authentication failed", Title: "Unauthorized"}, {Status: 409, Code: "totp_already_enabled", Title: "totp_already_enabled"}, {Status: 423, Code: "account_locked", Title: "account_locked"}, {Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"}, {Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"}},
	},
	{
		Method:      "POST",
		Path:        "/auth/refresh",
		Tag:         "Authentication",
		Summary:     "Rotate a refresh token",
		Description: "Use to obtain a fresh access/refresh pair without prompting the user for a password. Rotation revokes the presented token and stays within the same session family and original family_not_after cap. It preserves the primary-auth auth_time and any step_up_time unchanged; refresh never makes authentication fresh. Reuse or expiry invalidates the request and can revoke its whole family.",
		Request:     refreshRequest{},
		RequestExample: map[string]any{
			"refresh_token": "refresh-token-opaque",
		},
		Response: tokenResponse{},
		ResponseExample: map[string]any{
			"access_token":  "eyJhbGciOiJFZERTQSIs...",
			"refresh_token": "refresh-token-rotated",
			"token_type":    "Bearer",
			"expires_in":    600,
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/step-up/begin",
		Tag:         "Authentication",
		Summary:     "Begin MFA-only step-up",
		Description: "Use with an authenticated user bearer and its current refresh token after a guarded operation returns 403 step_up_required; this route is not freshness-guarded. The refresh token binds a persisted, purpose-specific, single-use challenge to the same user and session, and the step_up_token expires after five minutes. methods lists only currently enrolled, usable factors: otp for TOTP, backup_code for an unused backup code, and webauthn for a passkey. When webauthn is available, public_key is the direct user-bound assertion-options object with challenge, timeout, rpId, allowCredentials, and userVerification set to required (plus optional library extensions). This flow never enrolls a factor. Service and impersonation tokens return 403 step_up_forbidden; if no eligible factor is available, begin returns 403 step_up_not_available and the user must complete full primary login and any required enrollment instead. Accepts Idempotency-Key; the same key and body in the same raw Authorization scope replay the response, while a changed bearer uses a different scope. If canceled, abandon the challenge and let it expire.",
		Security:    "user",
		Request:     stepUpBeginRequest{},
		RequestExample: map[string]any{
			"refresh_token": "<current refresh token for this user bearer>",
		},
		Response: stepUpBeginResponse{},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 400, Code: "refresh_token is required", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 403, Code: "step_up_forbidden", Title: "step_up_forbidden"},
			{Status: 403, Code: "step_up_not_available", Title: "step_up_not_available"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
			{Status: 409, Code: "idempotency_in_progress", Title: "Idempotency In Progress"},
			{Status: 422, Code: "idempotency_conflict", Title: "Idempotency Conflict"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/step-up/complete",
		Tag:         "Authentication",
		Summary:     "Complete MFA-only step-up",
		Description: "Use the step_up_token and same current refresh token supplied to POST /auth/step-up/begin, plus exactly one proof: code for TOTP or an unused backup code, or credential for the user-verified WebAuthn assertion serialized from navigator.credentials.get using the begin response's public_key options. The authenticated user bearer and challenge must match the refresh session. A valid proof atomically consumes the one-use challenge and proof, rotates the refresh token within the original session family without extending family_not_after, preserves primary-auth auth_time and amr, and adds step_up_time; normal refresh preserves both timestamps without making them newer. Failed factor proofs return 401 authentication failed without consuming the persisted challenge, proof, or refresh session, subject to rate limits and account lockout. step_up_not_available is begin-only. Replace both stored tokens only after success. Accepts Idempotency-Key: use a new key for a different proof because a same-key/same-body retry replays the prior response and the same key with a different body conflicts; a changed bearer uses a different raw Authorization scope. After an ambiguous network failure, do not automatically retry. If canceled, abandon the challenge and let it expire.",
		Security:    "user",
		Request:     stepUpCompleteRequest{},
		RequestExample: map[string]any{
			"refresh_token": "<current refresh token for this user bearer>",
			"step_up_token": "<step_up_token returned by begin>",
			"code":          "123456",
		},
		Response: tokenResponse{},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 400, Code: "refresh_token and step_up_token are required", Title: "Invalid Request"},
			{Status: 400, Code: "exactly one of code or credential is required", Title: "Invalid Request"},
			{Status: 400, Code: "invalid WebAuthn response", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 403, Code: "step_up_forbidden", Title: "step_up_forbidden"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
			{Status: 409, Code: "idempotency_in_progress", Title: "Idempotency In Progress"},
			{Status: 422, Code: "idempotency_conflict", Title: "Idempotency Conflict"},
		},
	},


	{
		Method:      "POST",
		Path:        "/auth/logout",
		Tag:         "Authentication",
		Summary:     "Revoke a refresh-token family",
		Description: "Use when a client signs out. The operation is intentionally idempotent: missing, malformed, unknown, expired, or already-revoked refresh tokens produce 204 and do not disclose token state.",
		Request:     refreshRequest{},
		RequestExample: map[string]any{
			"refresh_token": "refresh-token-opaque",
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/introspect",
		Tag:         "Authentication",
		Summary:     "Introspect an access or refresh token",
		Description: "Use from a trusted service to check whether a token is active without exposing token material. The caller must authenticate with a service-kind EdDSA bearer token; inactive or missing input still returns 200 with active false.",
		Security:    "service",
		Request:     introspectRequest{},
		RequestExample: map[string]any{
			"token": "eyJhbGciOiJFZERTQSIs...",
		},
		Response: introspectResponse{},
		ResponseExample: map[string]any{
			"active":   true,
			"sub":      "01J8Z3USER000000000000001",
			"team":     "01J8Z3TEAM000000000000001",
			"kind":     "user",
			"perm_ver": 3,
			"exp":      1760000000,
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/client-credentials",
		Tag:         "Authentication",
		Summary:     "Obtain a service token",
		Description: "Use for service-to-service authentication. The caller presents the client ID (service user's username) and one-time secret created by POST /users/{id}/credentials with kind service.",
		Request:     clientCredentialsRequest{},
		RequestExample: map[string]any{
			"client_id":     "orders-service",
			"client_secret": "generated-service-secret",
		},
		Response: tokenResponse{},
		ResponseExample: map[string]any{
			"access_token":  "eyJhbGciOiJFZERTQSIs...",
			"refresh_token": "refresh-token-opaque",
			"token_type":    "Bearer",
			"expires_in":    600,
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "request body must be valid JSON", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/password-reset/request",
		Tag:         "Authentication",
		Summary:     "Request a password reset",
		Description: "Use when a user has lost a password. Submit a username or email; the endpoint always returns 204 so callers cannot enumerate accounts. A notification event is emitted only for an active matching account.",
		Request:     passwordResetRequest{},
		RequestExample: map[string]any{
			"login": "alice@example.test",
		},
		Errors: []apidocs.ErrorDoc{},
	},
	{
		Method:      "POST",
		Path:        "/auth/password-reset/confirm",
		Tag:         "Authentication",
		Summary:     "Confirm a password reset",
		Description: "Use with the one-time token delivered by the notification service. The new password must satisfy policy; success revokes all sessions and clears lockout state.",
		Request:     passwordResetConfirmRequest{},
		RequestExample: map[string]any{
			"token":        "reset-token-from-email",
			"new_password": "NewAtLeastTwelve1",
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "invalid_token", Title: "invalid_token"},
			{Status: 422, Code: "weak_password", Title: "weak_password"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/invite/accept",
		Tag:         "Authentication",
		Summary:     "Accept an invitation",
		Description: "Use from an invitation email to set the initial password and activate the invited account. The invitation email is marked verified; display_name is optional.",
		Request:     inviteAcceptRequest{},
		RequestExample: map[string]any{
			"token":        "invitation-token-from-email",
			"password":     "NewAtLeastTwelve1",
			"display_name": "Alice Example",
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "invalid_token", Title: "invalid_token"},
			{Status: 422, Code: "weak_password", Title: "weak_password"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/passkey/login/begin",
		Tag:         "Authentication",
		Summary:     "Begin passkey login",
		Description: "Use to begin a WebAuthn assertion. Pass an optional username for a scoped ceremony, or an empty body for discoverable credentials; the browser passes the returned publicKey options to navigator.credentials.get.",
		Request:     passkeyLoginBeginRequest{},
		RequestExample: map[string]any{
			"username": "alice",
		},
		Response: map[string]any{},
		ResponseExample: map[string]any{
			"publicKey": map[string]any{
				"challenge": "base64url-challenge",
				"timeout":   300000,
				"rpId":      "localhost",
				"allowCredentials": []any{
					map[string]any{
						"type": "public-key",
						"id":   "base64url-credential-id",
					},
				},
			},
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
	{
		Method:      "POST",
		Path:        "/auth/passkey/login/finish",
		Tag:         "Authentication",
		Summary:     "Finish passkey login",
		Description: "Use with the browser's PublicKeyCredential assertion response from the begin operation. A userVerified assertion can satisfy required MFA at primary login; this is separate from MFA-only step-up. Without user verification, enrolled TOTP triggers an initial MFA challenge; when TOTP is not enrolled, a required MFA policy yields a restricted enrollment token or, when deny_unenrolled is set, a 403 mfa_enrollment_denied. Without either TOTP or a required policy, login returns a full token pair. Successful access tokens include amr and primary-auth auth_time; only the separate step-up flow sets step_up_time.",
		Request:     map[string]any{},
		RequestExample: map[string]any{
			"id":    "base64url-credential-id",
			"rawId": "base64url-credential-id",
			"type":  "public-key",
			"response": map[string]any{
				"clientDataJSON":    "base64url-client-data",
				"authenticatorData": "base64url-authenticator-data",
				"signature":         "base64url-signature",
			},
		},
		Response: loginResponse{},
		ResponseExample: map[string]any{
			"mfa_required": true,
			"mfa_token":    "eyJhbGciOiJFZERTQSIs...",
			"mfa_methods":  []string{"otp"},
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 400, Code: "invalid WebAuthn response", Title: "Invalid Request"},
			{Status: 401, Code: "authentication failed", Title: "Unauthorized"},
			{Status: 403, Code: "mfa_enrollment_denied", Title: "mfa_enrollment_denied"},
			{Status: 423, Code: "account_locked", Title: "account_locked"},
			{Status: 429, Code: "authentication temporarily busy", Title: "Too Many Requests"},
			{Status: 500, Code: "authentication service unavailable", Title: "Internal Server Error"},
		},
	},
}

func init() {
		apidocsgen.RegisterRouterBuilder(func(cfg config.Config, q store.Q) (chi.Router, error) {
		server := httpapi.NewServer(cfg, nil)
		auditWriter := audit.NewWriter()
		service, err := New(Deps{Config: cfg, Q: q, Pool: nil, Audit: auditWriter})
		if err != nil {
			return nil, err
		}
		authRoutes := service.Routes()
		meRoutes := service.MeRoutes()
		authzRoutes := authz.NewRouter(q, service.Middleware())
		adminRoutes := httpapi.NewAdminRouter(q, auditWriter, service.Middleware(), cfg, service)
		server.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			switch {
			case strings.HasPrefix(r.URL.Path, "/authz/") || r.URL.Path == "/authz":
				authzRoutes.ServeHTTP(w, r)
			case strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/.well-known/jwks.json":
				authRoutes.ServeHTTP(w, r)
			case strings.HasPrefix(r.URL.Path, "/me/") || r.URL.Path == "/me":
				meRoutes.ServeHTTP(w, r)
			default:
				adminRoutes.ServeHTTP(w, r)
			}
		}))
		return apidocs.WithRoutes(server.Router(), authRoutes, meRoutes, authzRoutes, adminRoutes)
	})
}
