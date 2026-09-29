package passwd

import "testing"

func TestDefaultPolicy(t *testing.T) {
	tests := []struct {
		name string
		got  Policy
		want Policy
	}{
		{
			name: "built-in requirements",
			got:  DefaultPolicy(),
			want: Policy{MinLength: 12, RequireLetter: true, RequireDigit: true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if tt.got != tt.want {
				t.Fatalf("DefaultPolicy() = %+v, want %+v", tt.got, tt.want)
			}
		})
	}
}

func TestMergePolicy(t *testing.T) {
	tests := []struct {
		name  string
		rules []PolicyRule
		want  Policy
	}{
		{
			name: "higher priority rule wins per field",
			// Rules are ordered from highest to lowest priority.
			rules: []PolicyRule{
				{
					MinLength:    new(24),
					RequireUpper: new(true),
				},
				{
					MinLength:     new(18),
					RequireLetter: new(false),
					RequireDigit:  new(false),
					RequireSymbol: new(true),
				},
				{
					MinLength:    new(8),
					RequireUpper: new(false),
					RequireLower: new(true),
					RequireDigit: new(true),
				},
			},
			want: Policy{
				MinLength:     24,
				RequireLetter: false,
				RequireUpper:  true,
				RequireLower:  true,
				RequireDigit:  false,
				RequireSymbol: true,
			},
		},
		{
			name:  "single rule disables default letter and digit requirements",
			rules: []PolicyRule{{RequireLetter: new(false), RequireDigit: new(false)}},
			want: Policy{
				MinLength:     12,
				RequireLetter: false,
				RequireUpper:  false,
				RequireLower:  false,
				RequireDigit:  false,
				RequireSymbol: false,
			},
		},
		{
			name:  "unset fields fall through to defaults",
			rules: []PolicyRule{{MinLength: new(20)}},
			want:  Policy{MinLength: 20, RequireLetter: true, RequireDigit: true},
		},
		{
			name: "no rules use defaults",
			want: DefaultPolicy(),
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := MergePolicy(tt.rules); got != tt.want {
				t.Fatalf("MergePolicy() = %+v, want %+v", got, tt.want)
			}
		})
	}
}

func TestMergePolicyDoesNotMutateRules(t *testing.T) {
	minLength := 24
	requireLetter := true
	rules := []PolicyRule{{MinLength: &minLength, RequireLetter: &requireLetter}}
	original := rules[0]
	originalMinLength := minLength
	originalRequireLetter := requireLetter

	MergePolicy(rules)

	if rules[0] != original || minLength != originalMinLength || requireLetter != originalRequireLetter {
		t.Fatalf("MergePolicy mutated input rules: got %+v, want %+v", rules[0], original)
	}
}

func TestPolicyValidate(t *testing.T) {
	tests := []struct {
		name     string
		policy   Policy
		password string
		want     bool
	}{
		{
			name:     "minimum length counts runes",
			policy:   Policy{MinLength: 2},
			password: "éa",
			want:     true,
		},
		{
			name:     "shorter rune length is rejected",
			policy:   Policy{MinLength: 2},
			password: "é",
			want:     false,
		},
		{
			name:     "letter",
			policy:   Policy{MinLength: 1, RequireLetter: true},
			password: "a",
			want:     true,
		},
		{
			name:     "letter missing",
			policy:   Policy{MinLength: 1, RequireLetter: true},
			password: "1",
			want:     false,
		},
		{
			name:     "uppercase",
			policy:   Policy{MinLength: 1, RequireUpper: true},
			password: "A",
			want:     true,
		},
		{
			name:     "uppercase missing",
			policy:   Policy{MinLength: 1, RequireUpper: true},
			password: "a",
			want:     false,
		},
		{
			name:     "lowercase",
			policy:   Policy{MinLength: 1, RequireLower: true},
			password: "a",
			want:     true,
		},
		{
			name:     "lowercase missing",
			policy:   Policy{MinLength: 1, RequireLower: true},
			password: "A",
			want:     false,
		},
		{
			name:     "digit",
			policy:   Policy{MinLength: 1, RequireDigit: true},
			password: "7",
			want:     true,
		},
		{
			name:     "digit missing",
			policy:   Policy{MinLength: 1, RequireDigit: true},
			password: "a",
			want:     false,
		},
		{
			name:     "punctuation symbol",
			policy:   Policy{MinLength: 1, RequireSymbol: true},
			password: "!",
			want:     true,
		},
		{
			name:     "unicode symbol",
			policy:   Policy{MinLength: 1, RequireSymbol: true},
			password: "©",
			want:     true,
		},
		{
			name:     "symbol missing",
			policy:   Policy{MinLength: 1, RequireSymbol: true},
			password: "a",
			want:     false,
		},
		{
			name:     "default policy accepts 12 rune letter and digit password",
			policy:   DefaultPolicy(),
			password: "abcdefghijk1",
			want:     true,
		},
		{
			name:     "default policy rejects 11 rune password",
			policy:   DefaultPolicy(),
			password: "abcdefghij1",
			want:     false,
		},
		{
			name:     "default policy rejects password without digit",
			policy:   DefaultPolicy(),
			password: "abcdefghijkl",
			want:     false,
		},
		{
			name:     "default policy rejects password without letter",
			policy:   DefaultPolicy(),
			password: "123456789012",
			want:     false,
		},
		{
			name:     "default policy counts multibyte runes",
			policy:   DefaultPolicy(),
			password: "éééééééééé1a",
			want:     true,
		},
		{
			name:     "zero minimum length fails closed",
			policy:   Policy{},
			password: "",
			want:     false,
		},
		{
			name:     "empty password",
			policy:   DefaultPolicy(),
			password: "",
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.policy.Validate(tt.password); got != tt.want {
				t.Fatalf("Policy.Validate(%q) = %t, want %t", tt.password, got, tt.want)
			}
		})
	}
}
