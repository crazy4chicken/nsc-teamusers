package domain

// Resolution is the result for one requested permission.
//
// Explicit deny grants override all matching allows; otherwise any matching
// allow grants access. Matched is false when no grant applies.
type Resolution struct {
	Request Permission
	Matched bool
	Allowed bool
	Denied  bool
}

// GrantSet is a collection of grants that can resolve requested permissions.
type GrantSet []Permission


// Resolve resolves requests against grants. Deny-overrides is independent of
// grant order and scope specificity; permission segment matching is unchanged.
// Results retain request order and contain one entry per request.
func Resolve(grants []Permission, requests []Permission) []Resolution {
	resolutions := make([]Resolution, len(requests))
	for i, request := range requests {
		resolution := Resolution{Request: request}
		if request.Validate() != nil {
			resolutions[i] = resolution
			continue
		}
		for _, grant := range grants {
			if grant.Validate() != nil {
				continue
			}
			if request.Deny && !grant.Deny {
				continue
			}
			if !matchPermissionSegments(grant, request) {
				continue
			}
			resolution.Matched = true
			if grant.Deny {
				resolution.Denied = true
			} else {
				resolution.Allowed = true
			}
		}
		if resolution.Denied {
			resolution.Allowed = false
		}
		resolutions[i] = resolution
	}
	return resolutions
}

// Resolve resolves requests using this grant set.
func (g GrantSet) Resolve(requests []Permission) []Resolution {
	return Resolve([]Permission(g), requests)
}

func matchPermissionSegments(grant, request Permission) bool {
	return matchSegment(grant.Resource, request.Resource) &&
		matchSegment(grant.Action, request.Action) &&
		matchSegment(grant.Scope, request.Scope)
}
