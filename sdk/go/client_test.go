package iam

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestAllowDenyBeatsAllowRegardlessGrantOrder(t *testing.T) {
	for _, grants := range []string{
		`[{"key":"order:read:team"},{"key":"!order:read:team"}]`,
		`[{"key":"!order:read:team"},{"key":"order:read:team"}]`,
	} {
		permissions := permissionsFromJSON(t, `{"user_id":"usr_1","perm_ver":1,"grants":`+grants+`}`)
		allowed, reason := NewClient(nil, permissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
		if allowed || reason != "permission denied" {
			t.Fatalf("Allow() = (%v, %q), want (false, %q) for grants %s", allowed, reason, "permission denied", grants)
		}
	}
}

func TestAllowConditionFailingDenyFallsThroughToAllow(t *testing.T) {
	permissions := permissionsFromJSON(t, `{"user_id":"usr_1","perm_ver":1,"grants":[{"key":"!order:read:team","condition":"subject.id == \"other\""},{"key":"order:read:team"}]}`)
	allowed, reason := NewClient(nil, permissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
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

func TestAllowAppliesServerScopedGrantsOnlyToTheirTeam(t *testing.T) {
	snapshot, err := json.Marshal(map[string]any{
		"version":  2,
		"user_id":  "usr_1",
		"perm_ver": 1,
		"grants": []map[string]any{
			{"key": "order:read:any", "team_id": "team_a", "condition": `subject.id == "usr_1" && resource.team_id == "team_a"`},
			{"key": "!order:read:any", "team_id": "team_b"},
			{"key": "order:read:team"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version := r.URL.Query().Get("version"); version != "2" {
			t.Errorf("snapshot version query = %q, want 2", version)
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		_, _ = w.Write(snapshot)
	}))
	defer server.Close()
	permissions := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithHTTPClient(server.Client()))
	client := NewClient(nil, permissions)
	claims := testClaims()

	cases := []struct {
		name       string
		permission string
		resource   Resource
		allowed    bool
		reason     string
	}{
		{name: "team allow", permission: "order:read:any", resource: Resource{TeamID: "team_a"}, allowed: true, reason: "permission granted"},
		{name: "other team deny", permission: "order:read:any", resource: Resource{TeamID: "team_b"}, reason: "permission denied"},
		{name: "unrelated team", permission: "order:read:any", resource: Resource{TeamID: "team_c"}, reason: "no matching grant"},
		{name: "platform grant without membership", permission: "order:read:team", resource: Resource{TeamID: "team_c"}, allowed: true, reason: "permission granted"},
		{name: "team permission without resource team", permission: "order:read:team", reason: "resource team is missing"},
		{name: "scoped any without resource team", permission: "order:read:any", reason: "no matching grant"},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			allowed, reason := client.Allow(t.Context(), claims, testCase.permission, testCase.resource)
			if allowed != testCase.allowed || reason != testCase.reason {
				t.Fatalf("Allow() = (%v, %q), want (%v, %q)", allowed, reason, testCase.allowed, testCase.reason)
			}
		})
	}
}

func TestAllowConditionFalseExcludesCandidateButErrorRejectsDecision(t *testing.T) {
	newPermissions := func(grants []map[string]any) *PermissionsClient {
		payload, err := json.Marshal(map[string]any{
			"user_id":  "usr_1",
			"perm_ver": 1,
			"grants":   grants,
		})
		if err != nil {
			t.Fatal(err)
		}
		return permissionsFromJSON(t, string(payload))
	}
	falsePermissions := newPermissions([]map[string]any{
		{"key": "!order:read:team", "team_id": "team_a", "condition": `subject.id == "other"`},
		{"key": "order:read:team", "team_id": "team_a"},
	})
	allowed, reason := NewClient(nil, falsePermissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
	if !allowed || reason != "permission granted" {
		t.Fatalf("false condition Allow() = (%v, %q), want (true, permission granted)", allowed, reason)
	}

	errorDeny := map[string]any{
		"key":       "!order:read:team",
		"team_id":   "team_a",
		"condition": `resource.attrs["count"] > 1`,
	}
	allow := map[string]any{"key": "order:read:team", "team_id": "team_a"}
	for _, grants := range [][]map[string]any{{errorDeny, allow}, {allow, errorDeny}} {
		permissions := newPermissions(grants)
		allowed, reason := NewClient(nil, permissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{
			TeamID: "team_a",
			Attrs:  map[string]any{"count": "not-numeric"},
		})
		if allowed || reason != "condition_error" {
			t.Fatalf("error condition Allow() = (%v, %q), want (false, condition_error) for grants %#v", allowed, reason, grants)
		}
	}
}

func TestAllowDefersCompileErrorsUntilApplicable(t *testing.T) {
	testCases := []struct {
		name        string
		grants      string
		teamID      string
		wantAllowed bool
		wantReason  string
	}{
		{
			name:        "matching compile error before allow",
			grants:      `[{"key":"!order:read:team","team_id":"team_a","condition":"subject.id"},{"key":"order:read:team"}]`,
			teamID:      "team_a",
			wantReason:  "condition_error",
		},
		{
			name:        "matching compile error after allow",
			grants:      `[{"key":"order:read:team"},{"key":"!order:read:team","team_id":"team_a","condition":"subject.id"}]`,
			teamID:      "team_a",
			wantReason:  "condition_error",
		},
		{
			name:        "wrong team compile error is ignored",
			grants:      `[{"key":"!order:read:team","team_id":"team_b","condition":"subject.id"},{"key":"order:read:team"}]`,
			teamID:      "team_a",
			wantAllowed: true,
			wantReason:  "permission granted",
		},
		{
			name:        "wrong permission compile error is ignored",
			grants:      `[{"key":"!invoice:read:team","team_id":"team_a","condition":"subject.id"},{"key":"order:read:team"}]`,
			teamID:      "team_a",
			wantAllowed: true,
			wantReason:  "permission granted",
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			permissions := permissionsFromJSON(t, `{"user_id":"usr_1","perm_ver":1,"grants":`+testCase.grants+`}`)
			allowed, reason := NewClient(nil, permissions).Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: testCase.teamID})
			if allowed != testCase.wantAllowed || reason != testCase.wantReason {
				t.Fatalf("Allow() = (%v, %q), want (%v, %q)", allowed, reason, testCase.wantAllowed, testCase.wantReason)
			}
		})
	}
}

func TestClientAllowDoesNotFallbackForLegacySnapshots(t *testing.T) {
	cases := []struct {
		name   string
		status int
		body   string
	}{
		{name: "legacy body", status: http.StatusOK, body: `{"user_id":"usr_1","perm_ver":1,"grants":[{"key":"order:read:team"}]}`},
		{name: "structured version error", status: http.StatusBadRequest, body: `{"type":"about:blank","title":"Unsupported Permission Snapshot Version","status":400,"detail":"version=2 is required; legacy snapshots are not supported"}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			checkCalls := make(chan struct{}, 1)
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path == "/authz/check" {
					checkCalls <- struct{}{}
					_ = json.NewEncoder(w).Encode(map[string]any{"allow": true, "reason": "permission granted"})
					return
				}
				w.WriteHeader(testCase.status)
				_, _ = w.Write([]byte(testCase.body))
			}))
			defer server.Close()
			permissions := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithHTTPClient(server.Client()))
			client := NewClient(nil, permissions)
			allowed, reason := client.Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
			if allowed || reason != "invalid permission snapshot" {
				t.Fatalf("Allow() = (%v, %q), want explicit snapshot failure", allowed, reason)
			}
			select {
			case <-checkCalls:
				t.Fatal("snapshot protocol error silently fell back to /authz/check")
			default:
			}
		})
	}
}
