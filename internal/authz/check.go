package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"nsc-teamusers/internal/domain"
	"nsc-teamusers/internal/httpapi"
	"nsc-teamusers/internal/store"
)

type handler struct {
	resolver *Resolver
	now      func() time.Time
}

// NewRouter constructs the runtime authorization routes. The supplied
// middleware must authenticate the request before the service-only guard runs.
func NewRouter(q store.Q, authMW func(http.Handler) http.Handler) chi.Router {
	h := &handler{resolver: NewResolver(q), now: time.Now}
	router := chi.NewRouter()
	if authMW != nil {
		router.Use(authMW)
	}
	router.Use(h.requireService)
	router.Post("/authz/check", h.check)
	router.Get("/authz/permissions/{userID}", h.permissions)
	return router
}

type checkRequest struct {
	Subject    string       `json:"subject"`
	Permission string       `json:"permission"`
	Context    checkContext `json:"context"`
}

type checkContext struct {
	Resource checkResource `json:"resource"`
}

type checkResource struct {
	OwnerID string         `json:"owner_id"`
	TeamID  string         `json:"team_id"`
	Attrs   map[string]any `json:"attrs"`
}

type checkResponse struct {
	Allow   bool     `json:"allow"`
	Matched []string `json:"matched"`
	Reason  string   `json:"reason"`
}

type permissionsResponse struct {
	UserID  string          `json:"user_id"`
	PermVer int64           `json:"perm_ver"`
	Grants  []grantResponse `json:"grants"`
}

type grantResponse struct {
	Key       string  `json:"key"`
	Condition *string `json:"condition,omitempty"`
}

func (h *handler) requireService(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, ok := httpapi.SubjectFrom(r.Context())
		if !ok || subject.Kind != "service" {
			httpapi.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "a service subject is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (h *handler) check(w http.ResponseWriter, r *http.Request) {
	var request checkRequest
	if !decodeRequest(w, r, &request) {
		return
	}
	userID := strings.TrimSpace(request.Subject)
	if userID == "" {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "subject is required")
		return
	}
	requested, err := domain.Parse(request.Permission)
	if err != nil {
		httpapi.WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Permission", "permission must use resource:action:scope grammar")
		return
	}

	set, resolveErr := h.resolver.Resolve(r.Context(), userID)
	if errors.Is(resolveErr, pgx.ErrNoRows) {
		httpapi.WriteProblem(w, r, http.StatusNotFound, "Not Found", "the requested user was not found")
		return
	}
	if resolveErr != nil && !errors.Is(resolveErr, ErrUserDisabled) {
		httpapi.WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authorization service unavailable")
		return
	}

	now := time.Now()
	if h.now != nil {
		now = h.now()
	}
	values := domain.Context{
		Subject: domain.Subject{ID: userID, Kind: "user"},
		Resource: domain.Resource{
			OwnerID: request.Context.Resource.OwnerID,
			TeamID:  request.Context.Resource.TeamID,
			Attrs:   request.Context.Resource.Attrs,
		},
		Request: domain.Request{Time: now},
	}
	result := evaluate(r.Context(), set, requested, values, h.resolver.DenyEnabled)
	if errors.Is(resolveErr, ErrUserDisabled) {
		result = evaluationResult{Matched: []string{}, Reason: "user disabled"}
	}
	writeJSON(w, http.StatusOK, checkResponse{
		Allow: result.Allow, Matched: result.Matched, Reason: result.Reason,
	})
}

func (h *handler) permissions(w http.ResponseWriter, r *http.Request) {
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	set, resolveErr := h.resolver.Resolve(r.Context(), userID)
	if errors.Is(resolveErr, pgx.ErrNoRows) {
		httpapi.WriteProblem(w, r, http.StatusNotFound, "Not Found", "the requested user was not found")
		return
	}
	if resolveErr != nil && !errors.Is(resolveErr, ErrUserDisabled) {
		httpapi.WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authorization service unavailable")
		return
	}

	grants := make([]grantResponse, 0, len(set.Grants))
	for _, grant := range set.Grants {
		var condition *string
		if source := grant.ConditionSource(); source != "" {
			condition = new(string)
			*condition = source
		}
		grants = append(grants, grantResponse{Key: grant.Permission.String(), Condition: condition})
	}
	writeJSON(w, http.StatusOK, permissionsResponse{
		UserID: set.UserID, PermVer: set.PermVer, Grants: grants,
	})
}

type evaluationResult struct {
	Allow   bool
	Matched []string
	Reason  string
}

// evaluate is the pure in-memory portion shared by the remote check and unit
// tests. Condition errors are treated as false so one broken grant cannot
// widen access.
func evaluate(ctx context.Context, set *Set, requested domain.Permission, values domain.Context, denyEnabled bool) evaluationResult {
	result := evaluationResult{Matched: make([]string, 0), Reason: "no matching grant"}
	if set == nil {
		return result
	}
	conditionRejected := false
	matchedPermissions := make([]domain.Permission, 0, len(set.Grants))
	seenKeys := make(map[string]struct{}, len(set.Grants))
	for _, grant := range set.Grants {
		if grant.Permission.Deny && !denyEnabled {
			continue
		}
		matches := domain.Match(grant.Permission, requested)
		if !matches && denyEnabled && grant.Permission.Deny && !requested.Deny {
			// domain.Match intentionally requires equal deny bits. For the
			// opt-in v1.1 deny path, domain.Resolve supplies the precedence
			// hook that lets a deny row compete with an allow request.
			resolution := domain.Resolve([]domain.Permission{grant.Permission}, []domain.Permission{requested}, true)
			matches = len(resolution) == 1 && resolution[0].Matched
		}
		if !matches {
			continue
		}
		if grant.Condition != nil {
			ok, err := grant.Condition.EvalWithContext(ctx, values)
			if err != nil || !ok {
				conditionRejected = true
				continue
			}
		}
		matchedPermissions = append(matchedPermissions, grant.Permission)
		key := grant.Permission.String()
		if _, seen := seenKeys[key]; !seen {
			seenKeys[key] = struct{}{}
			result.Matched = append(result.Matched, key)
		}
	}
	if len(matchedPermissions) == 0 {
		if conditionRejected {
			result.Reason = "condition denied"
		}
		return result
	}
	if denyEnabled {
		resolution := domain.Resolve(matchedPermissions, []domain.Permission{requested}, true)
		if len(resolution) == 1 && resolution[0].Matched && !resolution[0].Allowed {
			result.Reason = "permission denied"
			return result
		}
	}
	result.Allow = true
	result.Reason = "permission granted"
	return result
}

func decodeRequest(w http.ResponseWriter, r *http.Request, dst any) bool {
	if err := json.NewDecoder(r.Body).Decode(dst); err != nil {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "request body must be valid JSON")
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
