package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/config"
	"teamusers/internal/domain"
	"teamusers/internal/store"
)

type adminGrantScopeContextKey struct{}

const (
	adminGrantScopeAny  = "any"
	adminGrantScopeTeam = "team"
)

func withAdminGrantScope(r *http.Request, scope string) *http.Request {
	ctx := context.WithValue(r.Context(), adminGrantScopeContextKey{}, scope)
	return r.WithContext(ctx)
}

func adminGrantScopeFrom(ctx context.Context) string {
	scope, _ := ctx.Value(adminGrantScopeContextKey{}).(string)
	return scope
}

// requirePermission enforces the resource permission for each administrative
// route after authentication has populated the subject. The admin plane is low
// QPS, so resolving permissions directly from the store on every request is
// intentional.
func (h *adminHandler) requirePermission(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, ok := SubjectFrom(r.Context())
		if !ok {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "an authenticated subject is required")
			return
		}
		if subject.Kind != "user" {
			WriteProblem(w, r, http.StatusForbidden, "Forbidden", "administrative access requires a user subject")
			return
		}

		area := adminPermissionArea(r.URL.Path)
		key := adminPermissionForPath(r.URL.Path)
		if area == "" || key == "" {
			WriteProblem(w, r, http.StatusForbidden, "Forbidden", "insufficient_permissions")
			return
		}
		requested, err := domain.Parse(key)
		if err != nil {
			WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authorization service unavailable")
			return
		}
		now := time.Now()
		permissionKeys, resolveErr := store.ListUnconditionalRolePermissions(r.Context(), h.q, subject.UserID, now)
		if resolveErr != nil {
			WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authorization service unavailable")
			return
		}
		grants := parsePermissionGrants(permissionKeys)
		if permissionGranted(grants, requested) {
			next.ServeHTTP(w, withAdminGrantScope(r, adminGrantScopeAny))
			return
		}
		if !isTeamScopedAdminArea(area) {
			WriteProblem(w, r, http.StatusForbidden, "Forbidden", "insufficient_permissions")
			return
		}

		teamID, targeted, targetErr := h.resolveAdminTeam(r.Context(), r, area)
		if targetErr != nil {
			if errors.Is(targetErr, pgx.ErrNoRows) {
				WriteProblem(w, r, http.StatusNotFound, "Not Found", "the requested resource was not found")
				return
			}
			WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authorization service unavailable")
			return
		}
		if !targeted || teamID == "" {
			WriteProblem(w, r, http.StatusForbidden, "Forbidden", "insufficient_permissions")
			return
		}

		teamPermissions, teamErr := store.ListUnconditionalTeamRolePermissions(r.Context(), h.q, subject.UserID, now)
		if teamErr != nil {
			WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authorization service unavailable")
			return
		}
		for _, candidate := range teamPermissions {
			if candidate.TeamID != teamID {
				continue
			}
			requestedTeam := domain.Permission{Resource: "iam", Action: area, Scope: "team"}
			if permissionGranted(parsePermissionGrants(candidate.Keys), requestedTeam) {
				next.ServeHTTP(w, withAdminGrantScope(r, adminGrantScopeTeam))
				return
			}
		}
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "insufficient_permissions")
	})
}

func parsePermissionGrants(keys []string) []domain.Permission {
	grants := make([]domain.Permission, 0, len(keys))
	for _, key := range keys {
		permission, err := domain.Parse(key)
		if err == nil {
			grants = append(grants, permission)
		}
	}
	return grants
}

func permissionGranted(grants []domain.Permission, requested domain.Permission) bool {
	resolution := domain.Resolve(grants, []domain.Permission{requested})
	return len(resolution) == 1 && resolution[0].Matched && resolution[0].Allowed
}

func adminPathSegments(path string) []string {
	trimmed := strings.Trim(path, "/")
	if trimmed == "" {
		return nil
	}
	return strings.Split(trimmed, "/")
}

func adminPermissionArea(path string) string {
	segments := adminPathSegments(path)
	if len(segments) == 0 {
		return ""
	}
	if segments[0] == "users" && len(segments) >= 3 && segments[2] == "sessions" {
		return "sessions"
	}
	switch segments[0] {
	case "invitations", "users":
		return "users"
	case "teams":
		return "teams"
	case "groups":
		return "groups"
	case "roles":
		return "roles"
	case "permissions":
		return "permissions"
	case "bindings":
		return "bindings"
	case "audit":
		return "audit"
	default:
		return ""
	}
}

func isTeamScopedAdminArea(area string) bool {
	switch area {
	case "teams", "groups", "roles", "bindings":
		return true
	default:
		return false
	}
}

func (h *adminHandler) resolveAdminTeam(ctx context.Context, r *http.Request, area string) (string, bool, error) {
	segments := adminPathSegments(r.URL.Path)
	switch area {
	case "teams":
		if len(segments) < 2 || segments[1] == "" {
			return "", false, nil
		}
		team, err := store.GetTeam(ctx, h.q, segments[1])
		if err != nil {
			return "", true, err
		}
		return team.ID, true, nil
	case "groups":
		if len(segments) >= 2 && segments[1] != "" {
			group, err := store.GetGroup(ctx, h.q, segments[1])
			if err != nil {
				return "", true, err
			}
			return group.TeamID, true, nil
		}
		if r.Method == http.MethodPost {
			return h.resolveAdminBodyTeam(ctx, r, "team_id")
		}
		teamID := strings.TrimSpace(r.URL.Query().Get("team_id"))
		if teamID == "" {
			return "", false, nil
		}
		team, err := store.GetTeam(ctx, h.q, teamID)
		if err != nil {
			return "", true, err
		}
		return team.ID, true, nil
	case "roles":
		if len(segments) >= 2 && segments[1] != "" {
			role, err := store.GetRole(ctx, h.q, segments[1])
			if err != nil {
				return "", true, err
			}
			if role.TeamID == nil {
				return "", true, nil
			}
			return *role.TeamID, true, nil
		}
		if r.Method == http.MethodPost {
			return h.resolveAdminBodyTeam(ctx, r, "team_id")
		}
		teamID := strings.TrimSpace(r.URL.Query().Get("team_id"))
		if teamID == "" {
			return "", false, nil
		}
		team, err := store.GetTeam(ctx, h.q, teamID)
		if err != nil {
			return "", true, err
		}
		return team.ID, true, nil
	case "bindings":
		if len(segments) >= 2 && segments[1] != "" {
			binding, err := store.GetRoleBinding(ctx, h.q, segments[1])
			if err != nil {
				return "", true, err
			}
			if binding.TeamID == nil {
				return "", true, nil
			}
			return *binding.TeamID, true, nil
		}
		if r.Method != http.MethodPost {
			return "", false, nil
		}
		raw, present, err := adminBodyField(r, "role_id")
		if err != nil {
			return "", false, err
		}
		if !present {
			return "", false, nil
		}
		var roleID string
		if json.Unmarshal(raw, &roleID) != nil {
			return "", false, nil
		}
		roleID = strings.TrimSpace(roleID)
		if roleID == "" {
			return "", false, nil
		}
		role, err := store.GetRole(ctx, h.q, roleID)
		if err != nil {
			return "", true, err
		}
		if role.TeamID == nil {
			return "", true, nil
		}
		return *role.TeamID, true, nil
	default:
		return "", false, nil
	}
}

func (h *adminHandler) resolveAdminBodyTeam(ctx context.Context, r *http.Request, field string) (string, bool, error) {
	raw, present, err := adminBodyField(r, field)
	if err != nil {
		return "", false, err
	}
	if !present {
		return "", false, nil
	}
	teamID, err := decodeNullableString(raw)
	if err != nil || teamID == nil {
		return "", false, nil
	}
	team, err := store.GetTeam(ctx, h.q, *teamID)
	if err != nil {
		return "", true, err
	}
	return team.ID, true, nil
}

func adminBodyField(r *http.Request, field string) (json.RawMessage, bool, error) {
	if r.Body == nil {
		return nil, false, nil
	}
	body, err := io.ReadAll(r.Body)
	if err != nil {
		return nil, false, err
	}
	_ = r.Body.Close()
	r.Body = io.NopCloser(bytes.NewReader(body))
	if len(bytes.TrimSpace(body)) == 0 {
		return nil, false, nil
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(body, &values); err != nil {
		return nil, false, nil
	}
	value, present := values[field]
	return value, present, nil
}

func adminPermissionForPath(path string) string {
	area := adminPermissionArea(path)
	if area == "" {
		return ""
	}
	return "iam:" + area + ":any"
}

type adminHandler struct {
	q     store.Q
	audit *auditlog.Writer
	cfg   config.Config
}
type adminProblemError struct {
	status int
	detail string
}

func (e *adminProblemError) Error() string { return e.detail }

func validationError(detail string) error {
	return &adminProblemError{status: http.StatusBadRequest, detail: detail}
}

func unprocessableError(detail string) error {
	return &adminProblemError{status: http.StatusUnprocessableEntity, detail: detail}
}
func forbiddenError(detail string) error {
	return &adminProblemError{status: http.StatusForbidden, detail: detail}
}

func writeValidationError(w http.ResponseWriter, r *http.Request, err error) bool {
	var problem *adminProblemError
	if !errors.As(err, &problem) {
		return false
	}
	WriteProblem(w, r, problem.status, http.StatusText(problem.status), problem.detail)
	return true
}

// NewAdminRouter constructs the protected administrative HTTP plane.
func NewAdminRouter(q store.Q, audit *auditlog.Writer, authMW func(http.Handler) http.Handler, cfg config.Config) chi.Router {
	if audit == nil {
		audit = auditlog.NewWriter()
	}
	cfg = cfg.WithDefaults()
	h := &adminHandler{q: q, audit: audit, cfg: cfg}
	router := chi.NewRouter()
	if authMW != nil {
		router.Use(authMW)
		router.Use(h.requireSubject)
		router.Use(h.requirePermission)
	}

	for _, route := range []struct {
		path string
		get  http.HandlerFunc
		post http.HandlerFunc
	}{
		{path: "/users", get: h.listUsers, post: h.createUser},
		{path: "/teams", get: h.listTeams, post: h.createTeam},
		{path: "/groups", get: h.listGroups, post: h.createGroup},
		{path: "/roles", get: h.listRoles, post: h.createRole},
		{path: "/permissions", get: h.listPermissions, post: h.registerPermission},
		{path: "/bindings", get: h.listBindings, post: h.createBinding},
		{path: "/audit", get: h.listAudit},
	} {
		router.Get(route.path, route.get)
		if route.post != nil {
			router.Post(route.path, route.post)
		}
	}
	router.Post("/invitations", h.createInvitation)
	router.Delete("/invitations/{userID}", h.cancelInvitation)

	router.Route("/invitations", func(r chi.Router) {
		r.Post("/", h.createInvitation)
		r.Post("/{userID}/resend", h.resendInvitation)
		r.Delete("/{userID}", h.cancelInvitation)
	})

	router.Route("/users", func(r chi.Router) {
		r.Get("/", h.listUsers)
		r.Post("/", h.createUser)
		r.Post("/batch", h.batchUserStatus)
		r.Post("/import", h.importUsers)
		r.Get("/{id}", h.getUser)
		r.Patch("/{id}", h.patchUser)
		r.Delete("/{id}", h.deleteUser)
		r.Post("/{id}/disable", h.disableUser)
		r.Post("/{id}/approve", h.approveUser)
		r.Post("/{id}/credentials", h.createUserCredential)
		r.Delete("/{id}/totp", h.deleteUserTOTP)
		r.Get("/{id}/sessions", h.listUserSessions)
		r.Delete("/{id}/sessions", h.deleteAllUserSessions)
		r.Delete("/{id}/sessions/{sid}", h.deleteUserSession)
	})
	router.Route("/teams", func(r chi.Router) {
		r.Get("/", h.listTeams)
		r.Post("/", h.createTeam)
		r.Get("/{id}", h.getTeam)
		r.Patch("/{id}", h.patchTeam)
		r.Delete("/{id}", h.deleteTeam)
	})
	router.Route("/groups", func(r chi.Router) {
		r.Get("/", h.listGroups)
		r.Post("/", h.createGroup)
		r.Get("/{id}", h.getGroup)
		r.Patch("/{id}", h.patchGroup)
		r.Delete("/{id}", h.deleteGroup)
		r.Post("/{id}/members/batch", h.batchGroupMembers)
		r.Put("/{id}/members", h.putMember)
		r.Delete("/{id}/members", h.deleteMember)
		r.Delete("/{id}/members/{userID}", h.deleteMember)
	})
	router.Route("/roles", func(r chi.Router) {
		r.Get("/", h.listRoles)
		r.Post("/", h.createRole)
		r.Get("/{id}", h.getRole)
		r.Patch("/{id}", h.patchRole)
		r.Delete("/{id}", h.deleteRole)
		r.Put("/{id}/permissions", h.setRolePermissions)
	})
	router.Route("/permissions", func(r chi.Router) {
		r.Get("/", h.listPermissions)
		r.Post("/", h.registerPermission)
	})
	router.Route("/bindings", func(r chi.Router) {
		r.Get("/", h.listBindings)
		r.Post("/", h.createBinding)
		r.Delete("/{id}", h.deleteBinding)
	})
	router.Route("/audit", func(r chi.Router) {
		r.Get("/", h.listAudit)
	})
	return router
}

func (h *adminHandler) requireSubject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if _, ok := SubjectFrom(r.Context()); !ok {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "an authenticated subject is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *adminHandler) withTx(ctx context.Context, fn func(context.Context, store.Tx) error) error {
	return store.WithAdminTx(ctx, h.q, fn)
}

func (h *adminHandler) auditEntry(r *http.Request, teamID *string, action, target string, before, after any) auditlog.Entry {
	var actorID *string
	if subject, ok := SubjectFrom(r.Context()); ok && subject.UserID != "" {
		actorID = &subject.UserID
	}
	return auditlog.Entry{
		TeamID:  teamID,
		ActorID: actorID,
		Action:  action,
		Target:  target,
		Before:  before,
		After:   after,
	}
}

type permissionOutboxPayload struct {
	Type    string    `json:"type"`
	UserIDs []string  `json:"user_ids"`
	TeamID  *string   `json:"team_id"`
	At      time.Time `json:"at"`
}

func appendOutboxPayload(ctx context.Context, q store.Q, topic string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = store.AppendOutboxEvent(ctx, q, store.OutboxEvent{Topic: topic, Payload: data})
	return err
}

func appendPermissionChange(ctx context.Context, q store.Q, userIDs []string, teamID *string) error {
	if userIDs == nil {
		userIDs = []string{}
	}
	return appendOutboxPayload(ctx, q, "perm.changed", permissionOutboxPayload{
		Type: "perm.changed", UserIDs: userIDs, TeamID: teamID, At: time.Now().UTC(),
	})
}

func appendUserDisabledEvents(ctx context.Context, q store.Q, userID string, teamID *string) error {
	if err := appendPermissionChange(ctx, q, []string{userID}, teamID); err != nil {
		return err
	}
	payload := permissionOutboxPayload{
		Type: "user.disabled", UserIDs: []string{userID}, TeamID: teamID, At: time.Now().UTC(),
	}
	if err := appendOutboxPayload(ctx, q, "user.disabled", payload); err != nil {
		return err
	}
	return appendOutboxPayload(ctx, q, "notify.user.disabled", map[string]string{"user_id": userID})
}

func appendNotifyEvent(ctx context.Context, q store.Q, topic string, payload any) error {
	return appendOutboxPayload(ctx, q, "notify."+topic, payload)
}

func bumpUserPermVers(ctx context.Context, q store.Q, userIDs []string) error {
	seen := make(map[string]struct{}, len(userIDs))
	for _, userID := range userIDs {
		if userID == "" {
			continue
		}
		if _, ok := seen[userID]; ok {
			continue
		}
		seen[userID] = struct{}{}
		if _, err := store.BumpUserPermVer(ctx, q, userID); err != nil {
			return err
		}
	}
	return nil
}

func decodeJSON(w http.ResponseWriter, r *http.Request, dst any) bool {
	decoder := json.NewDecoder(r.Body)
	if err := decoder.Decode(dst); err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "request body must be valid JSON")
		return false
	}
	return true
}

func parsePage(w http.ResponseWriter, r *http.Request) (string, int, bool) {
	cursor := strings.TrimSpace(r.URL.Query().Get("cursor"))
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "limit must be a positive integer")
			return "", 0, false
		}
		limit = value
	}
	return cursor, limit, true
}

func parseAuditPage(w http.ResponseWriter, r *http.Request) (int64, int, bool) {
	limit := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("limit")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "limit must be a positive integer")
			return 0, 0, false
		}
		limit = value
	}
	cursor := int64(0)
	if raw := strings.TrimSpace(r.URL.Query().Get("cursor")); raw != "" {
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil || value < 0 {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "cursor must be a non-negative integer")
			return 0, 0, false
		}
		cursor = value
	}
	return cursor, limit, true
}

func writeItems(w http.ResponseWriter, items any, next string) {
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func writeAuditItems(w http.ResponseWriter, items any, next int64) {
	writeJSON(w, http.StatusOK, map[string]any{"items": items, "next_cursor": next})
}

func writeCreated(w http.ResponseWriter, value any) {
	writeJSON(w, http.StatusCreated, value)
}
