package httpapi

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"teamusers/internal/config"
)

func TestTrustedRealIPHonorsConfiguredCIDR(t *testing.T) {
	cfg := loadTrustedProxyConfig(t, "10.0.0.0/8")
	got := remoteAddrAfterMiddleware(t, trustedRealIP(cfg.TrustedProxies), "10.24.8.4:4321", "198.51.100.7, 203.0.113.8")
	if got != "198.51.100.7" {
		t.Fatalf("trusted CIDR peer got RemoteAddr %q, want first forwarded address", got)
	}
}

func TestTrustedRealIPHonorsConfiguredSingleIP(t *testing.T) {
	cfg := loadTrustedProxyConfig(t, "192.0.2.10")
	got := remoteAddrAfterMiddleware(t, trustedRealIP(cfg.TrustedProxies), "192.0.2.10:4321", "198.51.100.9")
	if got != "198.51.100.9" {
		t.Fatalf("trusted single-IP peer got RemoteAddr %q, want forwarded address", got)
	}
}

func TestTrustedRealIPRetainsLoopbackBehavior(t *testing.T) {
	got := remoteAddrAfterMiddleware(t, trustedRealIP(nil), "127.0.0.1:4321", "198.51.100.10")
	if got != "198.51.100.10" {
		t.Fatalf("loopback peer got RemoteAddr %q, want forwarded address", got)
	}
}

func TestTrustedRealIPIgnoresForwardedAddressFromUntrustedPeer(t *testing.T) {
	got := remoteAddrAfterMiddleware(t, trustedRealIP(nil), "203.0.113.9:4321", "198.51.100.11")
	if got != "203.0.113.9:4321" {
		t.Fatalf("untrusted peer got RemoteAddr %q, want direct peer", got)
	}
}

func TestLoadTrustedProxiesRejectsInvalidEntry(t *testing.T) {
	t.Setenv("TEAMUSERS_TRUSTED_PROXIES", "10.0.0.0/8,not-an-ip")
	if _, err := config.Load(); err == nil {
		t.Fatal("config.Load accepted an invalid trusted proxy entry")
	}
}

func TestLoadTrustedProxiesEmptyDefault(t *testing.T) {
	t.Setenv("TEAMUSERS_TRUSTED_PROXIES", "")
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	if len(cfg.TrustedProxies) != 0 {
		t.Fatalf("empty trusted proxy setting produced %v, want no proxies", cfg.TrustedProxies)
	}
}

func loadTrustedProxyConfig(t *testing.T, raw string) config.Config {
	t.Helper()
	t.Setenv("TEAMUSERS_TRUSTED_PROXIES", raw)
	cfg, err := config.Load()
	if err != nil {
		t.Fatalf("config.Load: %v", err)
	}
	return cfg
}

func remoteAddrAfterMiddleware(t *testing.T, middleware func(http.Handler) http.Handler, remoteAddr, forwarded string) string {
	t.Helper()
	var got string
	next := http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		got = r.RemoteAddr
	})
	req := httptest.NewRequest(http.MethodGet, "http://example.test/", nil)
	req.RemoteAddr = remoteAddr
	req.Header.Set("X-Forwarded-For", forwarded)
	middleware(next).ServeHTTP(httptest.NewRecorder(), req)
	return got
}
