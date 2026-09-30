package httpapi

import (
	"context"
	"time"

	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

// ResolvePasswordPolicy loads the effective password rules for userID and
// merges their field-level overrides. Callers must surface the returned error;
// a failed lookup must never silently weaken or replace the policy.
func ResolvePasswordPolicy(ctx context.Context, q store.Q, userID string, now time.Time) (passwd.Policy, error) {
	return passwd.ResolvePolicy(ctx, q, userID, now)
}
