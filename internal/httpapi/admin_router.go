package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/config"
	"teamusers/internal/store"
)

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
