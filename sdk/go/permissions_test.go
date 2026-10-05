package iam

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestPermissionsCacheInvalidatesOnTokenPermVer(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if version := r.URL.Query().Get("version"); version != "2" {
			t.Errorf("snapshot version query = %q, want 2", version)
		}
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":  2,
			"user_id":  "usr_1",
			"perm_ver": requests.Load(),
			"grants":   []map[string]string{{"key": "order:read:team"}},
		})
	}))
	defer server.Close()

	client := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithTTL(time.Hour), WithHTTPClient(server.Client()))
	first, err := client.Get(t.Context(), "usr_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if first.PermVer != 1 {
		t.Fatalf("first PermVer = %d, want 1", first.PermVer)
	}
	if _, err := client.Get(t.Context(), "usr_1", 1); err != nil {
		t.Fatal(err)
	}
	if requests.Load() != 1 {
		t.Fatalf("same perm_ver caused %d requests, want 1", requests.Load())
	}
	second, err := client.Get(t.Context(), "usr_1", 2)
	if err != nil {
		t.Fatal(err)
	}
	if second.PermVer != 2 {
		t.Fatalf("second PermVer = %d, want 2", second.PermVer)
	}
	if requests.Load() != 2 {
		t.Fatalf("perm_ver change caused %d requests, want 2", requests.Load())
	}
}

func TestPermissionsV2PreservesScopeAndClampsCacheExpiry(t *testing.T) {
	deadline := time.Now().Add(30 * time.Second).UTC()
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		if version := r.URL.Query().Get("version"); version != "2" {
			t.Errorf("snapshot version query = %q, want 2", version)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version":     2,
			"user_id":     "usr_1",
			"perm_ver":    1,
			"valid_until": deadline.Format(time.RFC3339Nano),
			"grants": []map[string]any{{
				"key":       "order:read:team",
				"team_id":   "team_a",
				"condition": `subject.id == "usr_1"`,
			}},
		})
	}))
	defer server.Close()

	client := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithTTL(time.Hour), WithHTTPClient(server.Client()))
	entry, err := client.Get(t.Context(), "usr_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(entry.Grants) != 1 || entry.Grants[0].TeamID == nil || *entry.Grants[0].TeamID != "team_a" {
		t.Fatalf("scoped grant = %#v, want team_a", entry.Grants)
	}
	if entry.ValidUntil == nil || !entry.ValidUntil.Equal(deadline) {
		t.Fatalf("ValidUntil = %v, want %v", entry.ValidUntil, deadline)
	}
	cached := client.entries["usr_1"]
	if !cached.expiresAt.Equal(deadline) {
		t.Fatalf("cache expires at %v, want the earlier valid_until %v", cached.expiresAt, deadline)
	}
	*entry.Grants[0].TeamID = "changed"
	*entry.ValidUntil = time.Time{}
	second, err := client.Get(t.Context(), "usr_1", 1)
	if err != nil {
		t.Fatal(err)
	}
	if len(second.Grants) != 1 || second.Grants[0].TeamID == nil || *second.Grants[0].TeamID != "team_a" ||
		second.ValidUntil == nil || !second.ValidUntil.Equal(deadline) || requests.Load() != 1 {
		t.Fatalf("cached snapshot lost isolated scope/deadline: %#v, requests=%d", second, requests.Load())
	}
}

func TestPermissionsRejectsLegacyAndMalformedSnapshots(t *testing.T) {
	cases := []struct {
		name string
		body string
	}{
		{name: "unversioned", body: `{"user_id":"usr_1","perm_ver":1,"grants":[]}`},
		{name: "v1", body: `{"version":1,"user_id":"usr_1","perm_ver":1,"grants":[]}`},
		{name: "unknown version", body: `{"version":3,"user_id":"usr_1","perm_ver":1,"grants":[]}`},
		{name: "version type", body: `{"version":"2","user_id":"usr_1","perm_ver":1,"grants":[]}`},
		{name: "user id type", body: `{"version":2,"user_id":1,"perm_ver":1,"grants":[]}`},
		{name: "perm ver type", body: `{"version":2,"user_id":"usr_1","perm_ver":true,"grants":[]}`},
		{name: "grants type", body: `{"version":2,"user_id":"usr_1","perm_ver":1,"grants":["order:read:team"]}`},
		{name: "condition type", body: `{"version":2,"user_id":"usr_1","perm_ver":1,"grants":[{"key":"order:read:team","condition":true}]}`},
		{name: "empty team scope", body: `{"version":2,"user_id":"usr_1","perm_ver":1,"grants":[{"key":"order:read:team","team_id":""}]}`},
		{name: "invalid deadline", body: `{"version":2,"user_id":"usr_1","perm_ver":1,"valid_until":"tomorrow","grants":[]}`},
		{name: "expired deadline", body: `{"version":2,"user_id":"usr_1","perm_ver":1,"valid_until":"2000-01-01T00:00:00Z","grants":[]}`},
	}
	for _, testCase := range cases {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if version := r.URL.Query().Get("version"); version != "2" {
					t.Errorf("snapshot version query = %q, want 2", version)
				}
				_, _ = w.Write([]byte(testCase.body))
			}))
			defer server.Close()
			client := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithHTTPClient(server.Client()))
			if _, err := client.Get(t.Context(), "usr_1", 1); !errors.Is(err, errInvalidPermissionSnapshot) {
				t.Fatalf("Get() error = %v, want invalid snapshot error", err)
			}
		})
	}
}

func TestPermissionsIgnoreUnknownAdditiveProperties(t *testing.T) {
	const body = `{"version":2,"user_id":"usr_1","perm_ver":1,"future_snapshot":{"enabled":true},"grants":[{"key":"order:read:team","future_grant":{"revision":3}}]}`
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(body))
	}))
	defer server.Close()

	client := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithHTTPClient(server.Client()))
	entry, err := client.Get(t.Context(), "usr_1", 1)
	if err != nil {
		t.Fatalf("Get() error = %v, want unknown additive properties ignored", err)
	}
	if len(entry.Grants) != 1 || entry.Grants[0].Key != "order:read:team" {
		t.Fatalf("grants = %#v, want the known grant retained", entry.Grants)
	}
}

func TestPermissionsInvalidateRevokesInFlightResponses(t *testing.T) {
	testCases := []struct {
		name       string
		invalidate func(*PermissionsClient)
	}{
		{name: "per-user-event", invalidate: func(client *PermissionsClient) { client.Invalidate("usr_1") }},
		{name: "clear-all", invalidate: (*PermissionsClient).Clear},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			const staleSnapshot = `{"version":2,"user_id":"usr_1","perm_ver":1,"grants":[{"key":"order:read:team"}]}`
			const freshSnapshot = `{"version":2,"user_id":"usr_1","perm_ver":1,"grants":[]}`
			responseHeld := make(chan struct{})
			releaseResponse := make(chan struct{})
			var releaseOnce sync.Once
			release := func() { releaseOnce.Do(func() { close(releaseResponse) }) }
			var requests atomic.Int32
			var fallbackCalls atomic.Int32
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.URL.Path != "/authz/permissions/usr_1" {
					fallbackCalls.Add(1)
					_, _ = w.Write([]byte(`{"allow":true,"reason":"permission granted"}`))
					return
				}
				if requests.Add(1) == 1 {
					close(responseHeld)
					<-releaseResponse
					_, _ = w.Write([]byte(staleSnapshot))
					return
				}
				_, _ = w.Write([]byte(freshSnapshot))
			}))
			defer server.Close()
			defer release()

			permissions := NewPermissionsClient(server.URL, WithServiceToken("svc"), WithHTTPClient(server.Client()))
			client := NewClient(nil, permissions)
			type result struct {
				allowed bool
				reason  string
			}
			leaderResult := make(chan result, 1)
			go func() {
				allowed, reason := client.Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
				leaderResult <- result{allowed: allowed, reason: reason}
			}()
			select {
			case <-responseHeld:
			case <-time.After(5 * time.Second):
				t.Fatal("permission response was not held")
			}

			waiterContext := &permissionTestContext{Context: context.Background(), entered: make(chan struct{}, 1)}
			waiterResult := make(chan result, 1)
			go func() {
				allowed, reason := client.Allow(waiterContext, testClaims(), "order:read:team", Resource{TeamID: "team_a"})
				waiterResult <- result{allowed: allowed, reason: reason}
			}()
			select {
			case <-waiterContext.entered:
			case <-time.After(5 * time.Second):
				t.Fatal("waiter did not join the in-flight permission request")
			}

			testCase.invalidate(permissions)
			freshResult := make(chan result, 1)
			go func() {
				allowed, reason := client.Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
				freshResult <- result{allowed: allowed, reason: reason}
			}()
			select {
			case got := <-freshResult:
				if got.allowed || got.reason != "no matching grant" {
					t.Fatalf("post-invalidation Allow() = (%v, %q), want no matching grant", got.allowed, got.reason)
				}
			case <-time.After(5 * time.Second):
				t.Fatal("post-invalidation request did not fetch a fresh snapshot")
			}

			release()
			for _, outcome := range []struct {
				name string
				ch   <-chan result
			}{{name: "leader", ch: leaderResult}, {name: "waiter", ch: waiterResult}} {
				select {
				case got := <-outcome.ch:
					if got.allowed || got.reason != "invalid permission snapshot" {
						t.Errorf("%s Allow() = (%v, %q), want fail-closed invalid snapshot", outcome.name, got.allowed, got.reason)
					}
				case <-time.After(5 * time.Second):
					t.Errorf("%s did not finish after the held response was released", outcome.name)
				}
			}

			allowed, reason := client.Allow(t.Context(), testClaims(), "order:read:team", Resource{TeamID: "team_a"})
			if allowed || reason != "no matching grant" {
				t.Fatalf("cached post-invalidation Allow() = (%v, %q), want no matching grant", allowed, reason)
			}
			if requests.Load() != 2 {
				t.Errorf("permission requests = %d, want one held response and one fresh response", requests.Load())
			}
			if fallbackCalls.Load() != 0 {
				t.Errorf("authoritative fallback calls = %d, want no downgrade after invalidation", fallbackCalls.Load())
			}
		})
	}
}

type permissionTestContext struct {
	context.Context
	entered chan struct{}
}

func (c *permissionTestContext) Done() <-chan struct{} {
	select {
	case c.entered <- struct{}{}:
	default:
	}
	return c.Context.Done()
}
