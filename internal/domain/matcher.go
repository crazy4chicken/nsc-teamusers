package domain

// Match reports whether grant applies to request.
//
// Matching is segment-wise: a wildcard covers exactly one segment value and
// never crosses a colon boundary. The deny bit is part of the permission
// identity and therefore must match as well.
func Match(grant, request Permission) bool {
	if grant.Validate() != nil || request.Validate() != nil {
		return false
	}
	return grant.Deny == request.Deny &&
		matchSegment(grant.Resource, request.Resource) &&
		matchSegment(grant.Action, request.Action) &&
		matchSegment(grant.Scope, request.Scope)
}

func matchSegment(grant, request string) bool {
	return grant == "*" || grant == request
}
