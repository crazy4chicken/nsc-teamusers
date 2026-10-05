package authz

import "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

func docError(status int, code, title string) apidocs.ErrorDoc {
	return apidocs.ErrorDoc{Status: status, Code: code, Title: title}
}

// DocOperations is the service authorization route contract used by the
// OpenAPI generator.
var DocOperations = []apidocs.Operation{
	{
		Method:      "POST",
		Path:        "/authz/check",
		Tag:         "Authorization",
		Summary:     "Evaluate a permission",
		Description: "Use from a trusted application service to make a single authorization decision for a user and resource context. The caller must use a service-kind bearer token. Every non-platform (team-scoped) grant applies only to its matching active resource.team_id; team baselines are inherited by users with any unexpired group membership in that active team. Platform bindings with null team_id remain available without team membership, but an eligible member's applicable team deny still overrides a matching platform allow for that team's resource. A platform administrator without active membership does not inherit the baseline deny and retains independent platform grants. A requested :team permission without resource.team_id denies. A false condition excludes only that grant and, if nothing else matches, leaves reason no matching grant; an error evaluating any applicable condition fails the whole decision with reason condition_error. Explicit deny wins matching allows; there is no role/source priority. matched lists every applicable key that matched, sorted lexicographically. Set max_auth_age_seconds to require recent authentication and pass auth_time from the user's token; a missing, future, or stale auth_time returns allow=false with reason step_up_required.",
		Security:    "service",
		Request:     checkRequest{},
		RequestExample: map[string]any{
			"subject":              "01J8Z3USER000000000000001",
			"permission":           "orders:read:team",
			"auth_time":            int64(1727712000),
			"max_auth_age_seconds": int64(600),
			"context": map[string]any{
				"resource": map[string]any{
					"owner_id": "01J8Z3OWNER000000000000001",
					"team_id":  "01J8Z3TEAM000000000000001",
					"attrs":    map[string]any{"region": "us-east-1"},
				},
			},
		},
		Response:        checkResponse{},
		ResponseExample: map[string]any{"allow": true, "matched": []string{"orders:read:team"}, "reason": "permission granted"},
		Errors: []apidocs.ErrorDoc{
			docError(400, "subject is required", "Invalid Request"),
			docError(401, "a service subject is required", "Unauthorized"),
			docError(404, "the requested user was not found", "Not Found"),
			docError(422, "permission must use resource:action:scope grammar", "Invalid Permission"),
			docError(500, "authorization service unavailable", "Internal Server Error"),
		},
	},
	{
		Method:          "GET",
		Path:            "/authz/permissions/{userID}",
		Tag:             "Authorization",
		Summary:         "List effective grants",
		Description:     "Use from a trusted service to refresh a permission cache for one user. Send GET /authz/permissions/{userID}?version=2; the service-kind bearer token is required. Missing or non-2 versions return 400 rather than an unsafe flattened snapshot. The v2 response carries version, user_id, perm_ver, grants with optional condition and team_id, and optional RFC 3339 valid_until (the earliest future membership or binding expiry affecting grants). Platform grants omit team_id; scoped grants include a non-empty team_id. Clients must require response version=2 and all required v2 fields, strictly validate defined field and grant types/shapes, and ignore unknown additive fields at the snapshot or grant level. Unknown fields add no security semantics; future security-semantic changes require an explicit version. SDKs clamp cache expiry to valid_until.",
		Security:        "service",
		Response:        permissionsResponse{},
		ResponseExample: map[string]any{
			"version":  2,
			"user_id":  "01J8Z3USER000000000000001",
			"perm_ver": int64(3),
			"grants": []any{
				map[string]any{"key": "reports:read:any"},
				map[string]any{"key": "orders:read:team", "condition": "resource.attrs[\"region\"] == \"us-east-1\"", "team_id": "01J8Z3TEAM000000000000001"},
			},
			"valid_until": "2026-11-01T00:00:00Z",
		},
		Errors: []apidocs.ErrorDoc{
			docError(400, "version=2 is required; legacy snapshots are not supported", "Unsupported Permission Snapshot Version"),
			docError(401, "authentication failed", "Unauthorized"),
			docError(404, "the requested user was not found", "Not Found"),
			docError(500, "authorization service unavailable", "Internal Server Error"),
		},
	},
}

