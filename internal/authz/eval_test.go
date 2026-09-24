package authz

import (
	"context"
	"testing"
	"time"

	"teamusers/internal/domain"
)

func TestEvaluateSet(t *testing.T) {
	condition, err := domain.Compile(`subject.id == "usr_1" && resource.attrs["tier"] == "gold"`)
	if err != nil {
		t.Fatalf("Compile() error = %v", err)
	}
	wildcard := domain.Permission{Resource: "orders", Action: "*", Scope: "team"}
	requested := domain.Permission{Resource: "orders", Action: "read", Scope: "team"}
	baseContext := domain.Context{
		Subject:  domain.Subject{ID: "usr_1", Kind: "user"},
		Resource: domain.Resource{TeamID: "team_1", Attrs: map[string]any{"tier": "gold"}},
		Request:  domain.Request{Time: time.Now()},
	}

	tests := []struct {
		name       string
		set        *Set
		ctx        context.Context
		values     domain.Context
		wantAllow  bool
		wantReason string
		wantMatch  []string
	}{
		{
			name: "wildcard condition allows matching action",
			set:  &Set{UserID: "usr_1", Grants: []Grant{{Permission: wildcard, Condition: condition}}},
			ctx:  context.Background(), values: baseContext,
			wantAllow: true, wantReason: "permission granted", wantMatch: []string{"orders:*:team"},
		},
		{
			name: "wildcard condition denies nonmatching attributes",
			set:  &Set{UserID: "usr_1", Grants: []Grant{{Permission: wildcard, Condition: condition}}},
			ctx:  context.Background(), values: domain.Context{
				Subject: baseContext.Subject, Resource: domain.Resource{TeamID: "team_1", Attrs: map[string]any{"tier": "silver"}}, Request: baseContext.Request,
			},
			wantAllow: false, wantReason: "condition denied", wantMatch: []string{},
		},
		{
			name: "expired binding is absent from resolved set",
			// Resolver filters expires_at before constructing Set. This direct
			// set models that post-resolution state and must not grant access.
			set: &Set{UserID: "usr_1", Grants: []Grant{}},
			ctx: context.Background(), values: baseContext,
			wantAllow: false, wantReason: "no matching grant", wantMatch: []string{},
		},
		{
			name: "condition evaluation error fails closed",
			set:  &Set{UserID: "usr_1", Grants: []Grant{{Permission: requested, Condition: condition}}},
			ctx:  canceledContext(), values: baseContext,
			wantAllow: false, wantReason: "condition denied", wantMatch: []string{},
		},
		{
			name: "disabled user has empty set",
			set:  &Set{UserID: "usr_1", PermVer: 7, Grants: []Grant{}},
			ctx:  context.Background(), values: baseContext,
			wantAllow: false, wantReason: "no matching grant", wantMatch: []string{},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluate(tt.ctx, tt.set, requested, tt.values, false)
			if got.Allow != tt.wantAllow || got.Reason != tt.wantReason {
				t.Fatalf("evaluate() = %#v, want allow=%v reason=%q", got, tt.wantAllow, tt.wantReason)
			}
			if len(got.Matched) != len(tt.wantMatch) {
				t.Fatalf("evaluate().Matched = %#v, want %#v", got.Matched, tt.wantMatch)
			}
			for i := range tt.wantMatch {
				if got.Matched[i] != tt.wantMatch[i] {
					t.Fatalf("evaluate().Matched = %#v, want %#v", got.Matched, tt.wantMatch)
				}
			}
		})
	}
}

func canceledContext() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	return ctx
}
