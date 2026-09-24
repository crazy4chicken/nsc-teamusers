package authz

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"teamusers/internal/domain"
	"teamusers/internal/store"
)

// ErrUserDisabled indicates that the requested user exists but cannot receive
// effective permissions. The returned Set is always empty for this error.
var ErrUserDisabled = errors.New("user is disabled")

// Set is the effective permission set for one user.
type Set struct {
	UserID  string
	PermVer int64
	Grants  []Grant
}

// Grant is one permission expanded from a role binding. A nil Condition is
// unconditional.
type Grant struct {
	Permission domain.Permission
	Condition  *domain.Condition

	conditionSource string
}

// ConditionSource returns the original source for a compiled condition. It is
// used by the permissions cache endpoint; compiled expr programs are not a
// stable wire representation.
func (g Grant) ConditionSource() string {
	return g.conditionSource
}

// Resolver expands role bindings into effective grants.
type Resolver struct {
	Q           store.Q
	DenyEnabled bool
	Logger      *slog.Logger
	Now         func() time.Time
}

// NewResolver constructs a resolver with deny rows disabled, as required for
// the v1.0 authorization surface.
func NewResolver(q store.Q) *Resolver {
	return &Resolver{Q: q, Logger: slog.Default(), Now: time.Now}
}

// Resolve resolves one user's effective set using the default deny switch.
func Resolve(ctx context.Context, q store.Q, userID string) (*Set, error) {
	return NewResolver(q).Resolve(ctx, userID)
}

// Resolve expands direct and inherited bindings. The database work is capped
// at four queries: the user row, direct user bindings, group bindings joined to
// active memberships, and one ANY($1) role_permissions expansion.
func (r *Resolver) Resolve(ctx context.Context, userID string) (*Set, error) {
	set := &Set{UserID: userID, Grants: make([]Grant, 0)}
	if r == nil || r.Q == nil {
		return set, errors.New("authorization query handle must not be nil")
	}
	user, err := store.GetUser(ctx, r.Q, userID)
	if err != nil {
		return set, err
	}
	set.PermVer = user.PermVer
	if user.Status != "active" {
		return set, ErrUserDisabled
	}

	now := time.Now()
	if r.Now != nil {
		now = r.Now()
	}
	direct, err := store.ListDirectRoleBindings(ctx, r.Q, userID, now)
	if err != nil {
		return set, err
	}
	group, err := store.ListGroupRoleBindings(ctx, r.Q, userID, now)
	if err != nil {
		return set, err
	}
	bindings := make([]store.RoleBinding, 0, len(direct)+len(group))
	bindings = append(bindings, direct...)
	bindings = append(bindings, group...)

	roleIDs := make([]string, 0, len(bindings))
	seenRoles := make(map[string]struct{}, len(bindings))
	for _, binding := range bindings {
		if _, ok := seenRoles[binding.RoleID]; ok {
			continue
		}
		seenRoles[binding.RoleID] = struct{}{}
		roleIDs = append(roleIDs, binding.RoleID)
	}
	rolePermissions, err := store.ListRolePermissionsForRoles(ctx, r.Q, roleIDs)
	if err != nil {
		return set, err
	}

	logger := r.Logger
	if logger == nil {
		logger = slog.Default()
	}
	for _, binding := range bindings {
		condition, source, err := compileBindingCondition(binding.Condition)
		if err != nil {
			// Conditions are fail-closed per grant, not per request. A broken
			// condition must never turn an otherwise valid role into an allow.
			logger.Warn("skipping role binding with invalid condition",
				"binding_id", binding.ID, "role_id", binding.RoleID, "error", err)
			continue
		}
		for _, key := range rolePermissions[binding.RoleID] {
			permission, err := domain.Parse(key)
			if err != nil {
				logger.Warn("skipping role permission with invalid key",
					"binding_id", binding.ID, "role_id", binding.RoleID, "permission", key, "error", err)
				continue
			}
			if permission.Deny && !r.DenyEnabled {
				continue
			}
			set.Grants = append(set.Grants, Grant{
				Permission:      permission,
				Condition:       condition,
				conditionSource: source,
			})
		}
	}
	return set, nil
}

func compileBindingCondition(source *string) (*domain.Condition, string, error) {
	if source == nil || strings.TrimSpace(*source) == "" {
		return nil, "", nil
	}
	condition, err := domain.Compile(*source)
	if err != nil {
		return nil, "", fmt.Errorf("compile condition: %w", err)
	}
	return condition, *source, nil
}
