package iam

import "testing"

func TestPermissionMatchMatrix(t *testing.T) {
	tests := []struct {
		name    string
		grant   string
		request string
		allow   bool
	}{
		{name: "exact", grant: "order:read:team", request: "order:read:team", allow: true},
		{name: "action wildcard", grant: "order:*:team", request: "order:write:team", allow: true},
		{name: "scope wildcard", grant: "order:read:*", request: "order:read:any", allow: true},
		{name: "resource wildcard", grant: "*:read:team", request: "order:read:team", allow: false},
		{name: "wildcard does not cross segments", grant: "order:*:*", request: "order:read:team:extra", allow: false},
		{name: "different resource", grant: "invoice:read:team", request: "order:read:team", allow: false},
		{name: "deny prefix is part of identity", grant: "!order:read:team", request: "order:read:team", allow: false},
		{name: "matching deny", grant: "!order:read:team", request: "!order:read:team", allow: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := MatchKeys(test.grant, test.request); got != test.allow {
				t.Fatalf("MatchKeys(%q, %q) = %v, want %v", test.grant, test.request, got, test.allow)
			}
		})
	}
}

func TestPermissionParseDenyRoundTrip(t *testing.T) {
	permission, err := Parse("!order:read:team")
	if err != nil {
		t.Fatalf("Parse() error = %v", err)
	}
	if !permission.Deny || permission.Resource != "order" || permission.Action != "read" || permission.Scope != "team" {
		t.Fatalf("Parse() = %#v, want deny order:read:team", permission)
	}
	if got := permission.String(); got != "!order:read:team" {
		t.Fatalf("Permission.String() = %q, want %q", got, "!order:read:team")
	}

	for _, key := range []string{"!", "!order:read", "!order:read:invalid"} {
		if _, err := Parse(key); err == nil {
			t.Errorf("Parse(%q) succeeded, want error", key)
		}
	}
}
