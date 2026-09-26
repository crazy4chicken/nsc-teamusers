package httpapi

import (
	"time"

	"teamusers/internal/apidocs"
	"teamusers/internal/store"
)

// docError creates the problem metadata emitted for one documented failure.
func docError(status int, code, title string) apidocs.ErrorDoc {
	return apidocs.ErrorDoc{Status: status, Code: code, Title: title}
}

var (
	docInvalidRequest = docError(400, "request body must be valid JSON", "Invalid Request")
	docInvalidPage    = docError(400, "limit must be a positive integer", "Invalid Request")
	docUnauthorized   = docError(401, "authentication failed", "Unauthorized")
	docForbidden      = docError(403, "insufficient_permissions", "Forbidden")
	docNotFound       = docError(404, "the requested resource was not found", "Not Found")
	docConflict       = docError(409, "the resource already exists", "Conflict")
	docRateLimited    = docError(429, "authentication temporarily busy", "Too Many Requests")
	docInternal       = docError(500, "authentication service unavailable", "Internal Server Error")
)

// These small documentation-only types mirror self-service payloads whose
// handlers live in the authn package. Keeping them here avoids an import cycle
// while still emitting useful schemas for the duplicate route metadata.
type docProfileResponse struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Email           *string    `json:"email,omitempty"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type docProfilePatchRequest struct {
	Username    string `json:"username,omitempty"`
	DisplayName string `json:"display_name,omitempty"`
}

type docPasswordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

type docEmailChangeRequest struct {
	NewEmail string `json:"new_email"`
	Password string `json:"password"`
}

type docTokenRequest struct {
	Token string `json:"token"`
}

type docDeleteProfileRequest struct {
	Password string `json:"password"`
}

type docTOTPConfirmRequest struct {
	Code string `json:"code"`
}

type docBackupCodesRequest struct {
	Password string `json:"password"`
}

type docTOTPResponse struct {
	Secret     string `json:"secret"`
	OtpauthURL string `json:"otpauth_url"`
}

type docBackupCodesResponse struct {
	BackupCodes []string `json:"backup_codes"`
}

type docExportMembership struct {
	GroupID string `json:"group_id"`
	TeamID  string `json:"team_id"`
}

type docExportResponse struct {
	Profile              docProfileResponse    `json:"profile"`
	Memberships          []docExportMembership `json:"memberships"`
	EffectivePermissions []string              `json:"effective_permissions"`
	ActiveSessions       []SessionResponse     `json:"active_sessions"`
	TOTPEnabled          bool                  `json:"totp_enabled"`
	PasskeyCount         int                   `json:"passkey_count"`
}

type docWebAuthnCredential struct {
	ID       string            `json:"id"`
	RawID    string            `json:"rawId"`
	Type     string            `json:"type"`
	Response map[string]string `json:"response"`
}

type docPasskeyResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

var (
	docUserExample = map[string]any{
		"id":                "01J8Z3USER000000000000001",
		"username":          "alice",
		"email":             "alice@example.test",
		"display_name":      "Alice Example",
		"status":            "active",
		"perm_ver":          3,
		"failed_logins":     0,
		"email_verified_at": "2026-01-01T00:00:00Z",
		"created_at":        "2026-01-01T00:00:00Z",
		"updated_at":        "2026-01-01T00:00:00Z",
	}
	docUserUpdatedExample = map[string]any{
		"id":            "01J8Z3USER000000000000001",
		"username":      "alice",
		"email":         "alice@example.test",
		"display_name":  "Alice Smith",
		"status":        "active",
		"perm_ver":      3,
		"failed_logins": 0,
		"created_at":    "2026-01-01T00:00:00Z",
		"updated_at":    "2026-01-01T00:00:00Z",
	}
	docDisabledUserExample = map[string]any{
		"id":            "01J8Z3USER000000000000001",
		"username":      "alice",
		"email":         "alice@example.test",
		"display_name":  "Alice Example",
		"status":        "disabled",
		"perm_ver":      4,
		"failed_logins": 0,
		"created_at":    "2026-01-01T00:00:00Z",
		"updated_at":    "2026-01-01T00:00:00Z",
	}
	docApprovedUserExample = map[string]any{
		"id":                "01J8Z3USER000000000000001",
		"username":          "alice",
		"email":             "alice@example.test",
		"display_name":      "Alice Example",
		"status":            "active",
		"perm_ver":          1,
		"failed_logins":     0,
		"email_verified_at": "2026-01-01T00:00:00Z",
		"approved_at":       "2026-01-02T00:00:00Z",
		"approved_by":       "01J8Z3ADMIN000000000000001",
		"created_at":        "2026-01-01T00:00:00Z",
		"updated_at":        "2026-01-02T00:00:00Z",
	}
	docTeamExample = map[string]any{
		"id":         "01J8Z3TEAM000000000000001",
		"slug":       "acme",
		"name":       "Acme",
		"status":     "active",
		"created_at": "2026-01-01T00:00:00Z",
	}
	docUpdatedTeamExample = map[string]any{
		"id":         "01J8Z3TEAM000000000000001",
		"slug":       "acme",
		"name":       "Acme Europe",
		"status":     "active",
		"created_at": "2026-01-01T00:00:00Z",
	}
	docGroupExample = map[string]any{
		"id":      "01J8Z3GROUP000000000000001",
		"team_id": "01J8Z3TEAM000000000000001",
		"name":    "backend",
	}
	docUpdatedGroupExample = map[string]any{
		"id":      "01J8Z3GROUP000000000000001",
		"team_id": "01J8Z3TEAM000000000000001",
		"name":    "platform-backend",
	}
	docRoleExample = map[string]any{
		"id":      "01J8Z3ROLE000000000000001",
		"team_id": "01J8Z3TEAM000000000000001",
		"name":    "operator",
	}
	docUpdatedRoleExample = map[string]any{
		"id":      "01J8Z3ROLE000000000000001",
		"team_id": "01J8Z3TEAM000000000000001",
		"name":    "senior-operator",
	}
	docPermissionExample = map[string]any{
		"key":           "orders:read:team",
		"description":   "Read orders in a team",
		"registered_by": "orders-service",
		"created_at":    "2026-01-01T00:00:00Z",
	}
	docBindingExample = map[string]any{
		"id":           "01J8Z3BIND000000000000001",
		"team_id":      "01J8Z3TEAM000000000000001",
		"role_id":      "01J8Z3ROLE000000000000001",
		"subject_kind": "user",
		"subject_id":   "01J8Z3USER000000000000001",
		"condition":    "resource.team_id == subject.team_id",
		"expires_at":   "2026-02-01T00:00:00Z",
	}
)

// DocOperations is the administrative, self-service, and health route
// contract used by the OpenAPI generator.
var DocOperations = []apidocs.Operation{
	{
		Method:          "GET",
		Path:            "/healthz",
		Tag:             "Health",
		Summary:         "Check liveness",
		Description:     "Use this inexpensive unauthenticated probe to determine whether the HTTP process is alive. Load balancers and orchestrators call it without credentials.",
		Response:        map[string]string{},
		ResponseExample: map[string]string{"status": "ok"},
		Errors:          []apidocs.ErrorDoc{},
	},
	{
		Method:          "GET",
		Path:            "/readyz",
		Tag:             "Health",
		Summary:         "Check readiness",
		Description:     "Use this unauthenticated probe before routing traffic. It checks database readiness and returns not_ready while dependencies are unavailable.",
		Response:        map[string]string{},
		ResponseExample: map[string]string{"status": "ready"},
		Errors:          []apidocs.ErrorDoc{docError(503, "not_ready", "Service Unavailable")},
	},

	{
		Method:          "GET",
		Path:            "/users/",
		Tag:             "Users",
		Summary:         "List users",
		Description:     "Use from an administrator console to page through all users. Requires an active user bearer with iam:users:any; cursor is an opaque ULID returned by the previous page.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{docUserExample}, "next_cursor": ""},
		Errors:          []apidocs.ErrorDoc{docInvalidPage, docUnauthorized, docForbidden, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/users/",
		Tag:             "Users",
		Summary:         "Create a user",
		Description:     "Use from an administrator or provisioning workflow to create an active user. Password and initial_password are optional; password wins when both are supplied.",
		Security:        "admin",
		Request:         createUserRequest{},
		RequestExample:  map[string]any{"username": "alice", "email": "alice@example.test", "display_name": "Alice Example", "password": "AtLeastTwelve1"},
		Response:        store.User{},
		ResponseExample: docUserExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docConflict, docError(422, "weak_password", "Weak Password"), docInternal},
	},
	{
		Method:          "POST",
		Path:            "/users/batch",
		Tag:             "Users",
		Summary:         "Enable or disable users in batches",
		Description:     "Use for administrative bulk status changes. Up to 500 IDs are processed independently; each result records success or invalid_id, not_found, or operation_failed.",
		Security:        "admin",
		Request:         userBatchRequest{},
		RequestExample:  map[string]any{"ids": []string{"01J8Z3USER000000000000001", "01J8Z3USER000000000000002"}, "op": "disable"},
		Response:        map[string]any{},
		ResponseExample: map[string]any{"results": []any{map[string]any{"id": "01J8Z3USER000000000000001", "ok": true}, map[string]any{"id": "01J8Z3USER000000000000002", "ok": false, "error": "not_found"}}},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docError(422, "op must be disable or enable", "Invalid Operation"), docError(422, "a maximum of 500 ids is allowed", "Too Many Items"), docInternal},
	},
	{
		Method:      "POST",
		Path:        "/users/import",
		Tag:         "Users",
		Summary:     "Import users from CSV",
		Description: "Use for bulk provisioning from an administrator export. Send text/csv with exactly username,email,display_name,password columns and at most 500 data rows; each row is reported independently.",
		Security:    "admin",
		Response:    map[string]any{},
		ResponseExample: map[string]any{
			"results": []any{
				map[string]any{"row": 2, "username": "alice", "ok": true, "id": "01J8Z3USER000000000000001"},
				map[string]any{"row": 3, "username": "bob", "ok": false, "error": "weak_password"},
			},
		},
		Errors: []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docError(415, "Content-Type must be text/csv", "Unsupported Media Type"), docError(422, "CSV header must be username,email,display_name,password", "Invalid CSV"), docInternal},
	},
	{
		Method:          "GET",
		Path:            "/users/{id}",
		Tag:             "Users",
		Summary:         "Get a user",
		Description:     "Use to retrieve one administrative user record by ULID. Requires iam:users:any.",
		Security:        "admin",
		Response:        store.User{},
		ResponseExample: docUserExample,
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "PATCH",
		Path:            "/users/{id}",
		Tag:             "Users",
		Summary:         "Update a user",
		Description:     "Use for administrative profile or status changes. At least one of username, email, display_name, and status is required; status may be active or disabled.",
		Security:        "admin",
		Request:         patchUserRequest{},
		RequestExample:  map[string]any{"display_name": "Alice Smith", "status": "active"},
		Response:        store.User{},
		ResponseExample: docUserUpdatedExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/users/{id}",
		Tag:         "Users",
		Summary:     "Delete a user",
		Description: "Use for an administrative hard deletion. Cascaded records are removed and the operation is audited; prefer account erasure for self-service privacy requests.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/users/{id}/disable",
		Tag:             "Users",
		Summary:         "Disable a user",
		Description:     "Use as a dedicated administrative lock switch. It resets lockout state, revokes sessions, invalidates permissions, and emits the same lifecycle events as a disabled status update.",
		Security:        "admin",
		Response:        store.User{},
		ResponseExample: docDisabledUserExample,
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/users/{id}/approve",
		Tag:             "Users",
		Summary:         "Approve a pending user",
		Description:     "Use in approval registration mode after the user has verified email. The administrator's user bearer is recorded as approver; unverified accounts return email_not_verified.",
		Security:        "admin",
		Response:        store.User{},
		ResponseExample: docApprovedUserExample,
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docError(422, "email_not_verified", "Invalid Request"), docInternal},
	},
	{
		Method:          "POST",
		Path:            "/users/{id}/credentials",
		Tag:             "Users",
		Summary:         "Create or rotate a user credential",
		Description:     "Use to provision a password credential or a service credential. Service secrets are generated and returned exactly once; password hashes are never returned.",
		Security:        "admin",
		Request:         createCredentialRequest{},
		RequestExample:  map[string]any{"kind": "password", "password": "AtLeastTwelve1"},
		Response:        map[string]string{},
		ResponseExample: map[string]string{"user_id": "01J8Z3USER000000000000001", "username": "alice", "kind": "password"},
		Errors:          []apidocs.ErrorDoc{docError(400, "kind must be password or service", "Invalid Request"), docUnauthorized, docForbidden, docNotFound, docError(422, "weak_password", "Weak Password"), docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/users/{id}/totp",
		Tag:         "Users",
		Summary:     "Reset a user's TOTP",
		Description: "Use for administrative recovery when a user loses MFA access. It deletes active, pending, and backup-code credentials without requiring the user's TOTP code.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "GET",
		Path:            "/users/{id}/sessions",
		Tag:             "Sessions",
		Summary:         "List a user's sessions",
		Description:     "Use for administrative security review. Requires iam:sessions:any and returns only active session IDs and timestamps, never client metadata or refresh tokens.",
		Security:        "admin",
		Response:        []SessionResponse{},
		ResponseExample: []map[string]any{{"id": "8d7e5b3a0f6f4e1d...", "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-31T00:00:00Z"}},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/users/{id}/sessions",
		Tag:         "Sessions",
		Summary:     "Revoke every session for a user",
		Description: "Use for incident response or after an administrative password reset. It revokes all refresh sessions for the target user and returns no body.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/users/{id}/sessions/{sid}",
		Tag:         "Sessions",
		Summary:     "Revoke one user's session",
		Description: "Use to revoke one device session during security review. The session must belong to the path user; foreign IDs return not_found.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},

	{
		Method:          "GET",
		Path:            "/teams/",
		Tag:             "Teams",
		Summary:         "List teams",
		Description:     "Use from an administrator console to page through teams. Requires iam:teams:any.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{docTeamExample}, "next_cursor": ""},
		Errors:          []apidocs.ErrorDoc{docInvalidPage, docUnauthorized, docForbidden, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/teams/",
		Tag:             "Teams",
		Summary:         "Create a team",
		Description:     "Use when provisioning a new tenant or workspace. Slug and name are required; status defaults to active.",
		Security:        "admin",
		Request:         teamCreateRequest{},
		RequestExample:  map[string]any{"slug": "acme", "name": "Acme", "status": "active"},
		Response:        store.Team{},
		ResponseExample: docTeamExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docConflict, docInternal},
	},
	{
		Method:          "GET",
		Path:            "/teams/{id}",
		Tag:             "Teams",
		Summary:         "Get a team",
		Description:     "Use to retrieve one team by ULID for an administrative view or downstream provisioning step.",
		Security:        "admin",
		Response:        store.Team{},
		ResponseExample: docTeamExample,
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "PATCH",
		Path:            "/teams/{id}",
		Tag:             "Teams",
		Summary:         "Update a team",
		Description:     "Use to rename or change a team's slug/status. At least one field is required; status must be active or disabled.",
		Security:        "admin",
		Request:         teamPatchRequest{},
		RequestExample:  map[string]any{"name": "Acme Europe", "status": "active"},
		Response:        store.Team{},
		ResponseExample: docUpdatedTeamExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/teams/{id}",
		Tag:         "Teams",
		Summary:     "Delete a team",
		Description: "Use to remove a team and its dependent administrative records. The operation invalidates affected permission versions and is audited.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},

	{
		Method:          "GET",
		Path:            "/groups/",
		Tag:             "Groups",
		Summary:         "List groups in a team",
		Description:     "Use to page through groups for one team. team_id is required because groups are team-scoped; requires iam:groups:any.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{docGroupExample}, "next_cursor": ""},
		Errors:          []apidocs.ErrorDoc{docInvalidPage, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/groups/",
		Tag:             "Groups",
		Summary:         "Create a group",
		Description:     "Use to create a team-scoped group that can receive memberships and role bindings.",
		Security:        "admin",
		Request:         groupCreateRequest{},
		RequestExample:  map[string]any{"team_id": "01J8Z3TEAM000000000000001", "name": "backend"},
		Response:        store.Group{},
		ResponseExample: docGroupExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docConflict, docInternal},
	},
	{
		Method:          "GET",
		Path:            "/groups/{id}",
		Tag:             "Groups",
		Summary:         "Get a group",
		Description:     "Use to retrieve one group by ULID, including its owning team ID.",
		Security:        "admin",
		Response:        store.Group{},
		ResponseExample: docGroupExample,
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "PATCH",
		Path:            "/groups/{id}",
		Tag:             "Groups",
		Summary:         "Update a group",
		Description:     "Use to rename a group or move it to another team. At least one of team_id and name is required; memberships are updated when the team changes.",
		Security:        "admin",
		Request:         groupPatchRequest{},
		RequestExample:  map[string]any{"name": "platform-backend"},
		Response:        store.Group{},
		ResponseExample: docUpdatedGroupExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/groups/{id}",
		Tag:         "Groups",
		Summary:     "Delete a group",
		Description: "Use to remove a group and its memberships. Affected users' permission versions are invalidated.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/groups/{id}/members/batch",
		Tag:             "Groups",
		Summary:         "Add group members in a batch",
		Description:     "Use to bulk-populate a group. Up to 500 user IDs are processed independently; duplicate rows report already_member and unknown users report not_found.",
		Security:        "admin",
		Request:         groupMembersBatchRequest{},
		RequestExample:  map[string]any{"user_ids": []string{"01J8Z3USER000000000000001", "01J8Z3USER000000000000002"}},
		Response:        map[string]any{},
		ResponseExample: map[string]any{"results": []any{map[string]any{"id": "01J8Z3USER000000000000001", "ok": true}, map[string]any{"id": "01J8Z3USER000000000000002", "ok": false, "error": "already_member"}}},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docError(422, "a maximum of 500 user_ids is allowed", "Too Many Items"), docInternal},
	},
	{
		Method:          "PUT",
		Path:            "/groups/{id}/members",
		Tag:             "Groups",
		Summary:         "Add or replace a group membership",
		Description:     "Use to add a user to a group or update that membership's expiry. The operation is idempotent and returns the complete membership record.",
		Security:        "admin",
		Request:         membershipRequest{},
		RequestExample:  map[string]any{"user_id": "01J8Z3USER000000000000001", "expires_at": "2026-02-01T00:00:00Z"},
		Response:        store.Membership{},
		ResponseExample: map[string]any{"team_id": "01J8Z3TEAM000000000000001", "group_id": "01J8Z3GROUP000000000000001", "user_id": "01J8Z3USER000000000000001", "expires_at": "2026-02-01T00:00:00Z"},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:         "DELETE",
		Path:           "/groups/{id}/members",
		Tag:            "Groups",
		Summary:        "Remove a group member by request body",
		Description:    "Use to remove a membership when the client has the group ID but sends the user ID as JSON. The path variant with userID is equivalent and is preferred for idempotent URL-based clients.",
		Security:       "admin",
		Request:        membershipRequest{},
		RequestExample: map[string]any{"user_id": "01J8Z3USER000000000000001"},
		Errors:         []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/groups/{id}/members/{userID}",
		Tag:         "Groups",
		Summary:     "Remove a group member",
		Description: "Use to remove a membership by group and user ULIDs. Unknown group, user, or membership returns a generic not-found problem.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},

	{
		Method:          "GET",
		Path:            "/roles/",
		Tag:             "Roles",
		Summary:         "List roles",
		Description:     "Use to page through platform or team roles. team_id optionally filters by team; omitted or null-scoped roles are platform roles.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{docRoleExample}, "next_cursor": ""},
		Errors:          []apidocs.ErrorDoc{docInvalidPage, docUnauthorized, docForbidden, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/roles/",
		Tag:             "Roles",
		Summary:         "Create a role",
		Description:     "Use to define a platform-wide or team-scoped role. team_id may be a ULID or JSON null.",
		Security:        "admin",
		Request:         roleCreateRequest{},
		RequestExample:  map[string]any{"team_id": "01J8Z3TEAM000000000000001", "name": "operator"},
		Response:        store.Role{},
		ResponseExample: docRoleExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docConflict, docInternal},
	},
	{
		Method:          "GET",
		Path:            "/roles/{id}",
		Tag:             "Roles",
		Summary:         "Get a role",
		Description:     "Use to retrieve one role and its scope before binding or changing permissions.",
		Security:        "admin",
		Response:        store.Role{},
		ResponseExample: docRoleExample,
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "PATCH",
		Path:            "/roles/{id}",
		Tag:             "Roles",
		Summary:         "Update a role",
		Description:     "Use to rename a role or change its team scope. At least one field is required; team-scoped administrators cannot change team_id outside their scope.",
		Security:        "admin",
		Request:         rolePatchRequest{},
		RequestExample:  map[string]any{"name": "senior-operator"},
		Response:        store.Role{},
		ResponseExample: docUpdatedRoleExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/roles/{id}",
		Tag:         "Roles",
		Summary:     "Delete a role",
		Description: "Use to remove a role and all of its bindings. Affected users' permission versions are invalidated.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},
	{
		Method:          "PUT",
		Path:            "/roles/{id}/permissions",
		Tag:             "Roles",
		Summary:         "Set permissions on a role",
		Description:     "Use to replace the complete permission set of a role. permission_keys is canonical; permissions is accepted as a legacy alias when permission_keys is absent. Every key must already be registered, including the optional ! deny prefix; deny rows take precedence during authorization.",
		Security:        "admin",
		Request:         setRolePermissionsRequest{},
		RequestExample:  map[string]any{"permission_keys": []string{"orders:read:team", "orders:update:own"}},
		Response:        map[string]any{},
		ResponseExample: map[string]any{"role_id": "01J8Z3ROLE000000000000001", "permissions": []string{"orders:read:team", "orders:update:own"}},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docError(422, "permission must use resource:action:scope grammar", "Invalid Permission"), docError(422, "permission is not registered: orders:read:team", "Invalid Request"), docInternal},
	},

	{
		Method:          "GET",
		Path:            "/permissions/",
		Tag:             "Permissions",
		Summary:         "List registered permissions",
		Description:     "Use to populate policy editors and validate role changes. Requires iam:permissions:any and returns cursor pages.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{docPermissionExample}, "next_cursor": ""},
		Errors:          []apidocs.ErrorDoc{docInvalidPage, docUnauthorized, docForbidden, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/permissions/",
		Tag:             "Permissions",
		Summary:         "Register or update a permission",
		Description:     "Use when an application service introduces a permission key. Keys must follow resource:action:scope grammar, with an optional ! deny prefix; registration is an upsert and increments the global permission registry version.",
		Security:        "admin",
		Request:         permissionRequest{},
		RequestExample:  map[string]any{"key": "orders:read:team", "description": "Read orders in a team", "registered_by": "orders-service"},
		Response:        store.Permission{},
		ResponseExample: docPermissionExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docError(422, "permission must use resource:action:scope grammar", "Invalid Permission"), docInternal},
	},

	{
		Method:          "GET",
		Path:            "/bindings/",
		Tag:             "Bindings",
		Summary:         "List role bindings for a subject",
		Description:     "Use to inspect a user's or group's role assignments. Both subject_kind and subject_id are required; cursor pages are scoped to that subject.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{docBindingExample}, "next_cursor": ""},
		Errors:          []apidocs.ErrorDoc{docError(400, "subject_kind and subject_id are required", "Invalid Request"), docUnauthorized, docForbidden, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/bindings/",
		Tag:             "Bindings",
		Summary:         "Create a role binding",
		Description:     "Use to assign a role to a user or group. Optional team_id, condition, and expires_at constrain scope; conditions are compiled before persistence and fail closed at evaluation time.",
		Security:        "admin",
		Request:         bindingRequest{},
		RequestExample:  docBindingExample,
		Response:        store.RoleBinding{},
		ResponseExample: docBindingExample,
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docNotFound, docConflict, docError(422, "condition could not be compiled", "Invalid Condition"), docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/bindings/{id}",
		Tag:         "Bindings",
		Summary:     "Delete a role binding",
		Description: "Use to remove a role assignment. Affected users' permission versions are invalidated and the deletion is audited.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docInternal},
	},

	{
		Method:          "GET",
		Path:            "/audit/",
		Tag:             "Audit",
		Summary:         "List audit entries",
		Description:     "Use for compliance review and incident investigation. The append-only log supports an optional team filter and a numeric cursor; cursor 0 means the beginning and next_cursor 0 means no next page.",
		Security:        "admin",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"items": []any{map[string]any{"id": int64(1), "team_id": "01J8Z3TEAM000000000000001", "actor_id": "01J8Z3ADMIN000000000000001", "action": "user.created", "target": "01J8Z3USER000000000000001", "diff": map[string]any{"status": "active"}, "request_id": "req-01J8Z3", "at": "2026-01-01T00:00:00Z"}}, "next_cursor": int64(0)},
		Errors:          []apidocs.ErrorDoc{docError(400, "cursor must be a non-negative integer", "Invalid Request"), docUnauthorized, docForbidden, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/invitations/",
		Tag:             "Invitations",
		Summary:         "Create an invitation",
		Description:     "Use from an administrator provisioning workflow to create an invited user and send a one-time invitation token. Username and email must be unique; the plaintext token is emitted only through notification delivery.",
		Security:        "admin",
		Request:         invitationRequest{},
		RequestExample:  map[string]any{"email": "alice@example.test", "username": "alice", "display_name": "Alice Example"},
		Response:        map[string]string{},
		ResponseExample: map[string]string{"id": "01J8Z3USER000000000000001", "status": "invited"},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docForbidden, docError(422, "username or email already exists", "Invalid Request"), docInternal},
	},
	{
		Method:      "POST",
		Path:        "/invitations/{userID}/resend",
		Tag:         "Invitations",
		Summary:     "Resend an invitation",
		Description: "Use when an invited user did not receive the original message. The previous invitation token is invalidated and a fresh seven-day token is emitted through notifications.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docError(422, "account is not invited", "Invalid Request"), docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/invitations/{userID}",
		Tag:         "Invitations",
		Summary:     "Cancel an invitation",
		Description: "Use when an invitation must be withdrawn before acceptance. The target must remain invited; cancellation deletes the user and cascaded records.",
		Security:    "admin",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docForbidden, docNotFound, docError(422, "account is not invited", "Invalid Request"), docInternal},
	},

	{
		Method:          "GET",
		Path:            "/me",
		Tag:             "Self-service",
		Summary:         "Get the current profile",
		Description:     "Use from a signed-in user interface to display the authenticated user's profile. The identity is always taken from the user bearer subject; credentials and other users' data are never returned.",
		Security:        "user",
		Response:        docProfileResponse{},
		ResponseExample: map[string]any{"id": "01J8Z3USER000000000000001", "username": "alice", "email": "alice@example.test", "display_name": "Alice Example", "status": "active", "email_verified_at": "2026-01-01T00:00:00Z", "created_at": "2026-01-01T00:00:00Z"},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docNotFound, docInternal},
	},
	{
		Method:          "PATCH",
		Path:            "/me",
		Tag:             "Self-service",
		Summary:         "Update the current profile",
		Description:     "Use when a user edits their own username or display name. Username is trimmed using the same rules as administrative user updates; email changes use the two-step email endpoints. At least one of username or display_name is required.",
		Security:        "user",
		Request:         docProfilePatchRequest{},
		RequestExample:  map[string]any{"username": "alice-new", "display_name": "Alice Smith"},
		Response:        docProfileResponse{},
		ResponseExample: map[string]any{"id": "01J8Z3USER000000000000001", "username": "alice-new", "email": "alice@example.test", "display_name": "Alice Smith", "status": "active", "email_verified_at": "2026-01-01T00:00:00Z", "created_at": "2026-01-01T00:00:00Z"},
		Errors:          []apidocs.ErrorDoc{docError(400, "at least one of username or display_name is required", "Invalid Request"), docUnauthorized, docError(422, "username is required", "Invalid Request"), docError(422, "username must be a string", "Invalid Request"), docError(422, "unsupported_field", "Unsupported Field"), docError(422, "email change is not supported", "Unsupported Field"), docConflict, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/me",
		Tag:         "Self-service",
		Summary:     "Erase the current account",
		Description: "Use when a user requests irreversible account erasure. The password is rechecked; profile identifiers are anonymized, all credentials and sessions are removed, and the account is disabled.",
		Security:    "user",
		Request:     docDeleteProfileRequest{},
		RequestExample: map[string]any{
			"password": "CurrentAtLeastTwelve1",
		},
		Errors: []apidocs.ErrorDoc{docInvalidRequest, docError(401, "invalid_credentials", "invalid_credentials"), docRateLimited, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/me/password",
		Tag:             "Self-service",
		Summary:         "Change the current password",
		Description:     "Use when a signed-in user rotates their password. The current password is verified, the replacement must satisfy policy, and every refresh session (including the current one) is revoked. A first-login change_token from POST /auth/login is accepted as the bearer in place of an access token.",
		Security:        "user",
		Request:         docPasswordChangeRequest{},
		RequestExample:  map[string]any{"current_password": "OldAtLeastTwelve1", "new_password": "NewAtLeastTwelve2"},
		Response:        map[string]any{},
		ResponseExample: map[string]any{"message": "password changed; all sessions were revoked; sign in again", "sessions_revoked": true},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docError(401, "invalid_credentials", "invalid_credentials"), docError(422, "weak_password", "weak_password"), docRateLimited, docInternal},
	},
	{
		Method:         "POST",
		Path:           "/me/email",
		Tag:            "Self-service",
		Summary:        "Request an email change",
		Description:    "Use when a user wants to replace their email. The current password is required; a single-use verification token is sent to the new address and the profile remains unchanged until confirmation.",
		Security:       "user",
		Request:        docEmailChangeRequest{},
		RequestExample: map[string]any{"new_email": "alice.new@example.test", "password": "CurrentAtLeastTwelve1"},
		Errors:         []apidocs.ErrorDoc{docInvalidRequest, docError(401, "invalid_credentials", "invalid_credentials"), docError(422, "invalid_email", "invalid_email"), docError(422, "email_taken", "email_taken"), docRateLimited, docInternal},
	},
	{
		Method:         "POST",
		Path:           "/me/email/confirm",
		Tag:            "Self-service",
		Summary:        "Confirm an email change",
		Description:    "Use with the one-time token sent to the replacement address. The token is bound to the bearer subject; success updates email_verified_at and the email atomically.",
		Security:       "user",
		Request:        docTokenRequest{},
		RequestExample: map[string]any{"token": "email-change-token-from-email"},
		Errors:         []apidocs.ErrorDoc{docError(400, "invalid_token", "invalid_token"), docUnauthorized, docInternal},
	},
	{
		Method:          "GET",
		Path:            "/me/sessions",
		Tag:             "Sessions",
		Summary:         "List the current user's sessions",
		Description:     "Use in account security settings to show active refresh sessions. Returned IDs are opaque token digests and only contain created_at and expires_at.",
		Security:        "user",
		Response:        []SessionResponse{},
		ResponseExample: []map[string]any{{"id": "8d7e5b3a0f6f4e1d...", "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-31T00:00:00Z"}},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/me/sessions/{id}",
		Tag:         "Sessions",
		Summary:     "Revoke one own session",
		Description: "Use when a user signs out another browser or device. Foreign, expired, revoked, or unknown IDs all return the same 404 response.",
		Security:    "user",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docNotFound, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/me/totp/enroll",
		Tag:             "Self-service",
		Summary:         "Start TOTP enrollment",
		Description:     "Use in security settings to start MFA enrollment. The returned secret and otpauth URL are displayed once; the credential remains pending until a code is confirmed.",
		Security:        "user",
		Response:        docTOTPResponse{},
		ResponseExample: map[string]any{"secret": "JBSWY3DPEHPK3PXP", "otpauth_url": "otpauth://totp/teamusers:alice?secret=JBSWY3DPEHPK3PXP&issuer=teamusers"},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docError(409, "totp_already_enabled", "totp_already_enabled"), docInternal},
	},
	{
		Method:          "POST",
		Path:            "/me/totp/confirm",
		Tag:             "Self-service",
		Summary:         "Confirm TOTP enrollment",
		Description:     "Use after scanning the enrollment QR code. Submit the current six-digit code; the pending secret becomes active and ten one-time backup codes are returned.",
		Security:        "user",
		Request:         docTOTPConfirmRequest{},
		RequestExample:  map[string]any{"code": "123456"},
		Response:        docBackupCodesResponse{},
		ResponseExample: map[string]any{"backup_codes": []string{"abcd-1234-efgh-5678", "9ijk-lmno-0123-pqrs", "1111-2222-3333-4444"}},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docError(409, "totp_already_enabled", "totp_already_enabled"), docInternal},
	},
	{
		Method:          "POST",
		Path:            "/me/totp/backup-codes",
		Tag:             "Self-service",
		Summary:         "Regenerate TOTP backup codes",
		Description:     "Use when backup codes are exhausted or suspected exposed. The current password and an active TOTP enrollment are required; old codes are replaced atomically.",
		Security:        "user",
		Request:         docBackupCodesRequest{},
		RequestExample:  map[string]any{"password": "CurrentAtLeastTwelve1"},
		Response:        docBackupCodesResponse{},
		ResponseExample: map[string]any{"backup_codes": []string{"abcd-1234-efgh-5678", "9ijk-lmno-0123-pqrs", "1111-2222-3333-4444"}},
		Errors:          []apidocs.ErrorDoc{docInvalidRequest, docError(401, "invalid_credentials", "invalid_credentials"), docError(404, "mfa_not_enrolled", "mfa_not_enrolled"), docRateLimited, docInternal},
	},
	{
		Method:         "DELETE",
		Path:           "/me/totp",
		Tag:            "Self-service",
		Summary:        "Disable TOTP",
		Description:    "Use when a user removes MFA. Submit a current TOTP code or unused backup code; active TOTP, pending TOTP, and backup credentials are deleted.",
		Security:       "user",
		Request:        docTOTPConfirmRequest{},
		RequestExample: map[string]any{"code": "123456"},
		Errors:         []apidocs.ErrorDoc{docInvalidRequest, docUnauthorized, docInternal},
	},
	{
		Method:          "POST",
		Path:            "/me/passkeys/register/begin",
		Tag:             "Self-service",
		Summary:         "Begin passkey registration",
		Description:     "Use from a signed-in browser to add a WebAuthn credential. The browser passes the returned publicKey options to navigator.credentials.create; the ceremony expires after five minutes.",
		Security:        "user",
		Response:        map[string]any{},
		ResponseExample: map[string]any{"publicKey": map[string]any{"rp": map[string]any{"name": "teamusers", "id": "localhost"}, "user": map[string]any{"name": "alice", "displayName": "Alice Example", "id": "base64url-user-handle"}, "challenge": "base64url-challenge", "pubKeyCredParams": []any{map[string]any{"type": "public-key", "alg": -7}}, "attestation": "none"}},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docInternal},
	},
	{
		Method:      "POST",
		Path:        "/me/passkeys/register/finish",
		Tag:         "Self-service",
		Summary:     "Finish passkey registration",
		Description: "Use with the browser's PublicKeyCredential creation response. A valid response consumes the single-use challenge and stores only the credential material required for WebAuthn.",
		Security:    "user",
		Request:     docWebAuthnCredential{},
		RequestExample: map[string]any{
			"id":       "base64url-credential-id",
			"rawId":    "base64url-credential-id",
			"type":     "public-key",
			"response": map[string]any{"clientDataJSON": "base64url-client-data", "attestationObject": "base64url-attestation"},
		},
		Errors: []apidocs.ErrorDoc{docError(400, "invalid WebAuthn response", "Invalid Request"), docUnauthorized, docInternal},
	},
	{
		Method:          "GET",
		Path:            "/me/passkeys",
		Tag:             "Self-service",
		Summary:         "List own passkeys",
		Description:     "Use in account security settings to show registered passkey identifiers. Public keys and attestation data are never returned.",
		Security:        "user",
		Response:        []docPasskeyResponse{},
		ResponseExample: []map[string]any{{"id": "base64url-credential-id", "created_at": "2026-01-01T00:00:00Z"}},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docInternal},
	},
	{
		Method:      "DELETE",
		Path:        "/me/passkeys/{credID}",
		Tag:         "Self-service",
		Summary:     "Delete one own passkey",
		Description: "Use to remove a passkey by its unpadded base64url credential ID. Unknown IDs return the same not-found problem regardless of ownership.",
		Security:    "user",
		Errors:      []apidocs.ErrorDoc{docUnauthorized, docError(404, "the requested passkey was not found", "Not Found"), docInternal},
	},
	{
		Method:          "GET",
		Path:            "/me/export",
		Tag:             "Self-service",
		Summary:         "Export current account data",
		Description:     "Use to satisfy a data portability request. The response is an attachment containing profile, memberships, effective permissions, active sessions, and MFA/passkey counts; secrets and credential material are excluded.",
		Security:        "user",
		Response:        docExportResponse{},
		ResponseExample: map[string]any{"profile": map[string]any{"id": "01J8Z3USER000000000000001", "username": "alice", "email": "alice@example.test", "display_name": "Alice Example", "status": "active", "email_verified_at": "2026-01-01T00:00:00Z", "created_at": "2026-01-01T00:00:00Z"}, "memberships": []any{map[string]any{"group_id": "01J8Z3GROUP000000000000001", "team_id": "01J8Z3TEAM000000000000001"}}, "effective_permissions": []string{"orders:read:team"}, "active_sessions": []any{map[string]any{"id": "8d7e5b3a0f6f4e1d...", "created_at": "2026-01-01T00:00:00Z", "expires_at": "2026-01-31T00:00:00Z"}}, "totp_enabled": false, "passkey_count": 0},
		Errors:          []apidocs.ErrorDoc{docUnauthorized, docInternal},
	},
}

func init() {
	apidocs.RegisterOperations(DocOperations)
}
