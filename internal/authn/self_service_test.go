package authn

import (
	"reflect"
	"testing"

	"teamusers/internal/authz"
	"teamusers/internal/domain"
)

func TestEffectivePermissionKeys(t *testing.T) {
	parse := func(key string) domain.Permission {
		t.Helper()
		permission, err := domain.Parse(key)
		if err != nil {
			t.Fatalf("parse permission %q: %v", key, err)
		}
		return permission
	}
	condition, err := domain.Compile(`subject.kind == "user"`)
	if err != nil {
		t.Fatalf("compile condition: %v", err)
	}
	set := &authz.Set{Grants: []authz.Grant{
		{Permission: parse("me:write:team")},
		{Permission: parse("me:read:team")},
		{Permission: parse("!me:read:*")},
		{Permission: parse("me:write:team")},
		{Permission: parse("me:conditional:own"), Condition: condition},
		{Permission: parse("me:conditional-deny:own")},
		{Permission: parse("!me:conditional-deny:own"), Condition: condition},
	}}

	got := effectivePermissionKeys(set)
	want := []string{"me:conditional-deny:own", "me:write:team"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("effectivePermissionKeys() = %v, want %v", got, want)
	}

	if got := effectivePermissionKeys(nil); got == nil || len(got) != 0 {
		t.Fatalf("effectivePermissionKeys(nil) = %v, want a non-nil empty slice", got)
	}
}
