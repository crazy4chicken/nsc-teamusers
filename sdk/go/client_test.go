package iam

import (
	"encoding/json"
	"testing"
	"time"
)

func TestAllowDenyBeatsAllowRegardlessGrantOrder(t *testing.T) {
	for _, grants := range []string{
		`[{"key":"order:read:team"},{"key":"!order:read:team"}]`,
		`[{"key":"!order:read:team"},{"key":"order:read:team"}]`,
	} {
		permissions := permissionsFromJSON(t, `{"user_id":"usr_1","perm_ver":1,"grants":`+grants+`}`)
		allowed, reason := NewClient(nil, permissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{})
		if allowed || reason != "permission denied" {
			t.Fatalf("Allow() = (%v, %q), want (false, %q) for grants %s", allowed, reason, "permission denied", grants)
		}
	}
}

func TestAllowConditionFailingDenyFallsThroughToAllow(t *testing.T) {
	permissions := permissionsFromJSON(t, `{"user_id":"usr_1","perm_ver":1,"grants":[{"key":"!order:read:team","condition":"subject.id == \"other\""},{"key":"order:read:team"}]}`)
	allowed, reason := NewClient(nil, permissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{})
	if !allowed || reason != "permission granted" {
		t.Fatalf("Allow() = (%v, %q), want (true, %q)", allowed, reason, "permission granted")
	}
}

func TestGrantUnmarshalCachesDenyPermission(t *testing.T) {
	var grant Grant
	if err := json.Unmarshal([]byte(`{"key":"!order:read:team"}`), &grant); err != nil {
		t.Fatalf("unmarshal grant: %v", err)
	}
	want := Permission{Resource: "order", Action: "read", Scope: "team", Deny: true}
	if grant.permission != want {
		t.Fatalf("cached grant permission = %#v, want %#v", grant.permission, want)
	}
}

func permissionsFromJSON(t *testing.T, payload string) *PermissionsClient {
	t.Helper()
	var entry PermissionEntry
	if err := json.Unmarshal([]byte(payload), &entry); err != nil {
		t.Fatalf("unmarshal permissions: %v", err)
	}
	client := NewPermissionsClient("")
	client.entries[entry.UserID] = cachedPermissionEntry{
		entry:     &entry,
		expiresAt: time.Now().Add(time.Hour),
	}
	return client
}

func testClaims() Claims {
	return Claims{
		Subject: "usr_1",
		Kind:    "user",
		PermVer: 1,
		Expiry:  time.Now().Add(time.Hour),
	}
}
