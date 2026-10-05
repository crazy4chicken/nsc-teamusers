package httpapi

import "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

// DocImpersonationOperations describes the administrative impersonation route.
var DocImpersonationOperations = []apidocs.Operation{
	{
		Method:      "POST",
		Path:        "/impersonations",
		Tag:         "Impersonation",
		Summary:     "Start an audited user impersonation",
		Description: "Use for time-bounded administrative support as an active user. Requires iam:impersonate:any and a user bearer with positive auth_time or step_up_time no older than ten minutes; timestamps up to 30 seconds in the future are accepted. The target must be active, must not be a service account or the caller, and must not hold effective IAM permissions. The required reason is recorded with the actor, target, TTL, token jti, and exact expires_at in the append-only audit log. The returned user-kind access token has no refresh token or session, carries act and imp claims, sets auth_time to zero, and cannot use MFA-only step-up or satisfy freshness guards.",
		PermissionNote: "Requires a user bearer with positive `auth_time` or `step_up_time` no older than ten minutes; timestamps up to 30 seconds in the future are accepted. Otherwise returns 403 `step_up_required`.",
		Security:    "admin",
		Request:     impersonationRequest{},
		RequestExample: map[string]any{
			"user_id": "01J8Z3USER000000000000001", "reason": "investigate support request", "ttl_seconds": 300,
		},
		Response:        impersonationResponse{},
		ResponseExample: map[string]any{"access_token": "signed-user-token", "token_type": "Bearer", "expires_at": "2026-01-01T00:05:00Z"},
		Errors: []apidocs.ErrorDoc{
			docInvalidRequest,
			docError(400, "user_id is required", "Invalid Request"),
			docError(400, "reason must be at least 3 characters", "Invalid Request"),
			docError(400, "ttl_seconds must be between 1 and 900", "Invalid Request"),
			docUnauthorized,
			docForbidden,
			docError(403, "step_up_required", "Step-up Required"),
			docError(403, "the target user must be active", "Forbidden"),
			docError(403, "self-impersonation is not allowed", "Forbidden"),
			docError(403, "service accounts cannot be impersonated", "Forbidden"),
			docError(403, "the target user is not eligible for impersonation", "Forbidden"),
			docNotFound,
			docError(409, "idempotency_in_progress", "Idempotency In Progress"),
			docError(422, "idempotency_conflict", "Idempotency Conflict"),
			docInternal,
		},
	},
}

