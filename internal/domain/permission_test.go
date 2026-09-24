package domain

import "testing"

func TestParsePermissionGrammar(t *testing.T) {
	tests := []struct {
		name string
		key  string
		want Permission
	}{
		{name: "resource action scope", key: "orders:read:team", want: Permission{Resource: "orders", Action: "read", Scope: "team"}},
		{name: "resource punctuation", key: "order-items.v2:read-write:own", want: Permission{Resource: "order-items.v2", Action: "read-write", Scope: "own"}},
		{name: "wildcard action", key: "orders:*:any", want: Permission{Resource: "orders", Action: "*", Scope: "any"}},
		{name: "wildcard scope", key: "orders:read:*", want: Permission{Resource: "orders", Action: "read", Scope: "*"}},
		{name: "deny", key: "!orders:delete:own", want: Permission{Resource: "orders", Action: "delete", Scope: "own", Deny: true}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := Parse(tt.key)
			if err != nil {
				t.Fatalf("Parse(%q) error = %v", tt.key, err)
			}
			if got != tt.want {
				t.Fatalf("Parse(%q) = %#v, want %#v", tt.key, got, tt.want)
			}
			if got.String() != tt.key {
				t.Fatalf("String() = %q, want %q", got.String(), tt.key)
			}
			if err := got.Validate(); err != nil {
				t.Fatalf("Validate() error = %v", err)
			}
		})
	}
}

func TestParsePermissionGrammarRejects(t *testing.T) {
	keys := []string{
		"",
		":read:team",
		"Orders:read:team",
		"orders:Read:team",
		"orders:read:Team",
		"orders:read:tenant",
		"orders:read",
		"orders:read:team:extra",
		"orders/read/team",
		"orders:read/write:team",
		"orders:read:team ",
		"orders:read:*:extra",
		"orders:*read:team",
		"orders:read*:team",
		"! !orders:read:team",
		"!!orders:read:team",
		"!",
	}
	for _, key := range keys {
		t.Run(key, func(t *testing.T) {
			if _, err := Parse(key); err == nil {
				t.Fatalf("Parse(%q) error = nil, want rejection", key)
			}
		})
	}
}

func TestPermissionMatch(t *testing.T) {
	tests := []struct {
		name    string
		grant   Permission
		request Permission
		want    bool
	}{
		{name: "exact", grant: Permission{Resource: "orders", Action: "read", Scope: "team"}, request: Permission{Resource: "orders", Action: "read", Scope: "team"}, want: true},
		{name: "action wildcard", grant: Permission{Resource: "orders", Action: "*", Scope: "team"}, request: Permission{Resource: "orders", Action: "delete", Scope: "team"}, want: true},
		{name: "scope wildcard", grant: Permission{Resource: "orders", Action: "read", Scope: "*"}, request: Permission{Resource: "orders", Action: "read", Scope: "own"}, want: true},
		{name: "resource is not cross segment", grant: Permission{Resource: "orders", Action: "*", Scope: "team"}, request: Permission{Resource: "orders:read", Action: "team", Scope: "x"}, want: false},
		{name: "action mismatch", grant: Permission{Resource: "orders", Action: "read", Scope: "team"}, request: Permission{Resource: "orders", Action: "write", Scope: "team"}, want: false},
		{name: "deny differs", grant: Permission{Resource: "orders", Action: "read", Scope: "team", Deny: true}, request: Permission{Resource: "orders", Action: "read", Scope: "team"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := Match(tt.grant, tt.request); got != tt.want {
				t.Fatalf("Match(%#v, %#v) = %v, want %v", tt.grant, tt.request, got, tt.want)
			}
		})
	}
}
