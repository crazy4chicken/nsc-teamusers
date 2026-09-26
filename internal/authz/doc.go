package authz

import "teamusers/internal/apidocs"

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
		Description: "Use from a trusted application service to make a single authorization decision for a user and resource context. The caller must use a service-kind bearer token; deny keys prefixed with ! take precedence over matching allows, and condition failures fail closed.",
		Security:    "service",
		Request:     checkRequest{},
		RequestExample: map[string]any{
			"subject":    "01J8Z3USER000000000000001",
			"permission": "orders:read:team",
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
		Description:     "Use from a trusted service to refresh an authorization cache for one user. The service-kind bearer token is required; perm_ver lets consumers invalidate cached grants.",
		Security:        "service",
		Response:        permissionsResponse{},
		ResponseExample: map[string]any{"user_id": "01J8Z3USER000000000000001", "perm_ver": int64(3), "grants": []any{map[string]any{"key": "orders:read:team"}, map[string]any{"key": "orders:update:own", "condition": "resource.owner_id == subject.id"}}},
		Errors: []apidocs.ErrorDoc{
			docError(401, "authentication failed", "Unauthorized"),
			docError(404, "the requested user was not found", "Not Found"),
			docError(500, "authorization service unavailable", "Internal Server Error"),
		},
	},
}

func init() {
	apidocs.RegisterOperations(DocOperations)
}
