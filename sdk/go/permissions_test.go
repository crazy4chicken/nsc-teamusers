package iam

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestPermissionsCacheInvalidatesOnTokenPermVer(t *testing.T) {
	var requests atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requests.Add(1)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
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
