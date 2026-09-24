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
		{name: "deny prefix rejected", grant: "!order:read:team", request: "order:read:team", allow: false},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if got := MatchKeys(test.grant, test.request); got != test.allow {
				t.Fatalf("MatchKeys(%q, %q) = %v, want %v", test.grant, test.request, got, test.allow)
			}
		})
	}
}
