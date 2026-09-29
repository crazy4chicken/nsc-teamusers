package httpapi

import (
	"context"
	"fmt"
	"time"

	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

// ResolvePasswordPolicy loads the effective password rules for userID and
// merges their field-level overrides. Callers must surface the returned error;
// a failed lookup must never silently weaken or replace the policy.
func ResolvePasswordPolicy(ctx context.Context, q store.Q, userID string, now time.Time) (passwd.Policy, error) {
	policies, err := store.ListEffectivePasswordPolicies(ctx, q, userID, now)
	if err != nil {
		return passwd.Policy{}, fmt.Errorf("resolve password policy for user %q: %w", userID, err)
	}
	rules := make([]passwd.PolicyRule, len(policies))
	for i, policy := range policies {
		rules[i] = passwd.PolicyRule{
			MinLength:     policy.MinLength,
			RequireLetter: policy.RequireLetter,
			RequireUpper:  policy.RequireUpper,
			RequireLower:  policy.RequireLower,
			RequireDigit:  policy.RequireDigit,
			RequireSymbol: policy.RequireSymbol,
		}
	}
	return passwd.MergePolicy(rules), nil
}
