package authz

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/domain"
	"teamusers/internal/httpapi"
	"teamusers/internal/store"
)

const authTimeFutureSkew = 30 * time.Second

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
	Subject           string       `json:"subject"`
	Permission        string       `json:"permission"`
	AuthTime          int64        `json:"auth_time,omitempty"`
	MaxAuthAgeSeconds int64        `json:"max_auth_age_seconds,omitempty"`
	Context           checkContext `json:"context,omitempty"`
}

type checkContext struct {
	Resource checkResource `json:"resource,omitempty"`
}

type checkResource struct {
	OwnerID string         `json:"owner_id,omitempty"`
	TeamID  string         `json:"team_id,omitempty"`
	Attrs   map[string]any `json:"attrs,omitempty"`
}

type checkResponse struct {
	Allow   bool     `json:"allow"`
	Matched []string `json:"matched"`
	Reason  string   `json:"reason"`
}

type permissionsResponse struct {
	Version    int             `json:"version"`
	UserID     string          `json:"user_id"`
	PermVer    int64           `json:"perm_ver"`
	Grants     []grantResponse `json:"grants"`
	ValidUntil *time.Time      `json:"valid_until,omitempty"`
}

type grantResponse struct {
	Key       string  `json:"key"`
	Condition *string `json:"condition,omitempty"`
	TeamID    *string `json:"team_id,omitempty"`
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
	if request.MaxAuthAgeSeconds < 0 {
		httpapi.WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Auth Age", "max_auth_age_seconds must be non-negative")
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
			TeamID:  strings.TrimSpace(request.Context.Resource.TeamID),
			Attrs:   request.Context.Resource.Attrs,
		},
		Request: domain.Request{Time: now},
	}
	result := evaluate(r.Context(), set, requested, values)
	if errors.Is(resolveErr, ErrUserDisabled) {
		result = evaluationResult{Matched: []string{}, Reason: "user_disabled"}
	}
	if result.Allow && request.MaxAuthAgeSeconds > 0 && !authTimeFresh(request.AuthTime, request.MaxAuthAgeSeconds, now) {
		result = evaluationResult{Matched: []string{}, Reason: "step_up_required"}
	}
	writeJSON(w, http.StatusOK, checkResponse{
		Allow: result.Allow, Matched: result.Matched, Reason: result.Reason,
	})
}

func authTimeFresh(authTime, maxAgeSeconds int64, now time.Time) bool {
	if authTime <= 0 || maxAgeSeconds <= 0 {
		return false
	}
	age := now.Sub(time.Unix(authTime, 0))
	if age < -authTimeFutureSkew {
		return false
	}
	const maxDurationSeconds = int64((1<<63 - 1) / int64(time.Second))
	if maxAgeSeconds > maxDurationSeconds {
		return true
	}
	return age <= time.Duration(maxAgeSeconds)*time.Second
}

func (h *handler) permissions(w http.ResponseWriter, r *http.Request) {
	versions := r.URL.Query()["version"]
	if len(versions) != 1 || versions[0] != "2" {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Unsupported Permission Snapshot Version", "version=2 is required; legacy snapshots are not supported")
		return
	}
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
		grants = append(grants, grantResponse{
			Key: grant.Permission.String(), Condition: condition, TeamID: grant.TeamID,
		})
	}
	writeJSON(w, http.StatusOK, permissionsResponse{
		Version: 2, UserID: set.UserID, PermVer: set.PermVer, Grants: grants, ValidUntil: set.ValidUntil,
	})
}

type evaluationResult struct {
	Allow   bool
	Matched []string
	Reason  string
}

// evaluate is the pure in-memory portion shared by the remote check and unit
// tests. Team-scoped grants require an exact resource-team match; condition
// errors reject the whole applicable decision.
func evaluate(ctx context.Context, set *Set, requested domain.Permission, values domain.Context) evaluationResult {
	result := evaluationResult{Matched: make([]string, 0), Reason: "no matching grant"}
	if requested.Scope == "team" && strings.TrimSpace(values.Resource.TeamID) == "" {
		return result
	}
	if set == nil {
		return result
	}
	matchedPermissions := make([]domain.Permission, 0, len(set.Grants))
	seenKeys := make(map[string]struct{}, len(set.Grants))
	resourceTeamID := strings.TrimSpace(values.Resource.TeamID)
	for _, grant := range set.Grants {
		if grant.TeamID != nil && (resourceTeamID == "" || *grant.TeamID != resourceTeamID) {
			continue
		}
		matches := domain.Match(grant.Permission, requested)
		if !matches && grant.Permission.Deny && !requested.Deny {
			resolution := domain.Resolve([]domain.Permission{grant.Permission}, []domain.Permission{requested})
			matches = len(resolution) == 1 && resolution[0].Matched
		}
		if !matches {
			continue
		}
		if grant.conditionError != nil {
			return evaluationResult{Matched: []string{}, Reason: "condition_error"}
		}
		if grant.Condition != nil {
			ok, err := grant.Condition.EvalWithContext(ctx, values)
			if err != nil {
				return evaluationResult{Matched: []string{}, Reason: "condition_error"}
			}
			if !ok {
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
	sort.Strings(result.Matched)
	if len(matchedPermissions) == 0 {
		return result
	}
	resolution := domain.Resolve(matchedPermissions, []domain.Permission{requested})
	if len(resolution) == 1 && resolution[0].Matched && !resolution[0].Allowed {
		result.Reason = "permission denied"
		return result
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
