package domain

// ScopeRank returns the specificity rank used when grants conflict. A larger
// value is narrower and therefore wins. The wildcard scope is the broadest
// valid scope; invalid scopes rank below it.
func ScopeRank(scope string) int {
	switch scope {
	case "own":
		return 3
	case "team":
		return 2
	case "any":
		return 1
	case "*":
		return 0
	default:
		return -1
	}
}

// Resolution is the result for one requested permission.
//
// Grant is the highest-precedence matching grant. Matched is false when no
// grant applies. An explicit deny is represented by Denied=true and
// Allowed=false.
type Resolution struct {
	Request Permission
	Grant   Permission
	Matched bool
	Allowed bool
	Denied  bool
}

// GrantSet is a collection of grants that can resolve requested permissions.
type GrantSet []Permission

// Resolve resolves requests against grants. Deny rows are ignored unless the
// optional denyEnabled argument is present and true. Results retain request
// order and contain one entry per request.
func Resolve(grants []Permission, requests []Permission, denyEnabled ...bool) []Resolution {
	enableDeny := len(denyEnabled) > 0 && denyEnabled[0]
	resolutions := make([]Resolution, len(requests))
	for i, request := range requests {
		resolution := Resolution{Request: request}
		if request.Validate() != nil {
			resolutions[i] = resolution
			continue
		}
		var best Permission
		for _, grant := range grants {
			if grant.Validate() != nil {
				continue
			}
			if grant.Deny && !enableDeny {
				continue
			}
			if request.Deny && grant.Deny != request.Deny {
				continue
			}
			if !matchPermissionSegments(grant, request) {
				continue
			}
			if !resolution.Matched || higherPrecedence(grant, best) {
				best = grant
				resolution.Matched = true
			}
		}
		if resolution.Matched {
			resolution.Grant = best
			resolution.Denied = best.Deny
			resolution.Allowed = !best.Deny
		}
		resolutions[i] = resolution
	}
	return resolutions
}

// Resolve resolves requests using this grant set.
func (g GrantSet) Resolve(requests []Permission, denyEnabled ...bool) []Resolution {
	return Resolve([]Permission(g), requests, denyEnabled...)
}

// ResolveWithDeny is the explicit form of Resolve for callers that want the
// v1.1 deny switch to be visible at the call site.
func ResolveWithDeny(grants []Permission, requests []Permission, denyEnabled bool) []Resolution {
	return Resolve(grants, requests, denyEnabled)
}

func matchPermissionSegments(grant, request Permission) bool {
	return matchSegment(grant.Resource, request.Resource) &&
		matchSegment(grant.Action, request.Action) &&
		matchSegment(grant.Scope, request.Scope)
}

func higherPrecedence(candidate, current Permission) bool {
	if candidate.Deny != current.Deny {
		return candidate.Deny
	}
	return ScopeRank(candidate.Scope) > ScopeRank(current.Scope)
}
