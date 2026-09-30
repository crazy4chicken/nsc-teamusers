package config

import (
	"os"
	"strings"
	"testing"
	"time"
)

func isolateLoadEnvironment(t *testing.T) {
	t.Helper()
	names := []string{
		envConnectionString, envListenAddress, envListenPort, envNodeID, envLogLevel,
		envKeyDir, envNATSURL, envNotificationEndpoints, envNotificationSecret,
		envAuditRetentionDays, envAuditForwardEndpoints, envAuditForwardSecret, envPwnedPasswordsEnabled,
		envRegistrationMode, envTokenAudience, envLockoutThreshold, envLockoutDuration,
		envAccessTokenTTL, envRefreshTokenTTL, envSessionFamilyTTL,
		envWebAuthnRPID, envWebAuthnOrigin, envTrustedProxies, "HOST", "PORT",
	}
	type savedValue struct {
		name  string
		value string
		set   bool
	}
	saved := make([]savedValue, 0, len(names))
	for _, name := range names {
		value, set := os.LookupEnv(name)
		saved = append(saved, savedValue{name: name, value: value, set: set})
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unset %s: %v", name, err)
		}
	}
	t.Cleanup(func() {
		for _, entry := range saved {
			var err error
			if entry.set {
				err = os.Setenv(entry.name, entry.value)
			} else {
				err = os.Unsetenv(entry.name)
			}
			if err != nil {
				t.Errorf("restore %s: %v", entry.name, err)
			}
		}
	})
}

func TestLoadUsesDefaultTokenTTLs(t *testing.T) {
	isolateLoadEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default config: %v", err)
	}
	if cfg.AccessTokenTTL != DefaultAccessTokenTTL || cfg.RefreshTokenTTL != DefaultRefreshTokenTTL || cfg.SessionFamilyTTL != DefaultSessionFamilyTTL {
		t.Fatalf("token TTL defaults = (%s, %s, %s), want (%s, %s, %s)", cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.SessionFamilyTTL, DefaultAccessTokenTTL, DefaultRefreshTokenTTL, DefaultSessionFamilyTTL)
	}
}

func TestLoadTokenTTLFlagOverridesEnvironment(t *testing.T) {
	isolateLoadEnvironment(t)
	t.Setenv(envAccessTokenTTL, "2m")
	t.Setenv(envRefreshTokenTTL, "3h")
	t.Setenv(envSessionFamilyTTL, "4h")

	cfg, err := Load("--access-token-ttl", "5m", "--session-family-ttl=6h")
	if err != nil {
		t.Fatalf("load token TTLs: %v", err)
	}
	if cfg.AccessTokenTTL != 5*time.Minute || cfg.RefreshTokenTTL != 3*time.Hour || cfg.SessionFamilyTTL != 6*time.Hour {
		t.Fatalf("resolved token TTLs = (%s, %s, %s), want (5m, 3h, 6h)", cfg.AccessTokenTTL, cfg.RefreshTokenTTL, cfg.SessionFamilyTTL)
	}
}

func TestLoadRejectsInvalidTokenTTLDuration(t *testing.T) {
	tests := []struct {
		name    string
		args    []string
		message string
	}{
		{name: "access", args: []string{"--access-token-ttl", "not-a-duration"}, message: "invalid access token TTL"},
		{name: "refresh", args: []string{"--refresh-token-ttl", "not-a-duration"}, message: "invalid refresh token TTL"},
		{name: "family", args: []string{"--session-family-ttl", "not-a-duration"}, message: "invalid session family TTL"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			isolateLoadEnvironment(t)
			if _, err := Load(tt.args...); err == nil || !strings.Contains(err.Error(), tt.message) {
				t.Fatalf("Load() error = %v, want %q", err, tt.message)
			}
		})
	}
}

func TestLoadRequiresPositiveTokenTTLs(t *testing.T) {
	isolateLoadEnvironment(t)
	if _, err := Load("--access-token-ttl=0s"); err == nil || !strings.Contains(err.Error(), "access token TTL must be positive") {
		t.Fatalf("Load() error = %v, want non-positive access TTL rejection", err)
	}
}

func TestLoadRequiresSessionFamilyAtLeastRefreshTTL(t *testing.T) {
	t.Run("rejects shorter family", func(t *testing.T) {
		isolateLoadEnvironment(t)
		if _, err := Load("--refresh-token-ttl=2h", "--session-family-ttl=1h"); err == nil || !strings.Contains(err.Error(), "session family TTL must be at least refresh token TTL") {
			t.Fatalf("Load() error = %v, want shorter-family rejection", err)
		}
	})
	t.Run("accepts equal lifetime", func(t *testing.T) {
		isolateLoadEnvironment(t)
		cfg, err := Load("--refresh-token-ttl=2h", "--session-family-ttl=2h")
		if err != nil {
			t.Fatalf("load equal refresh and family TTLs: %v", err)
		}
		if cfg.SessionFamilyTTL != cfg.RefreshTokenTTL {
			t.Fatalf("session family TTL = %s, refresh TTL = %s", cfg.SessionFamilyTTL, cfg.RefreshTokenTTL)
		}
	})
}

func TestAuditRetentionDaysDefaultAndFlagOverride(t *testing.T) {
	isolateLoadEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default audit retention: %v", err)
	}
	if cfg.AuditRetentionDays != 0 {
		t.Fatalf("default audit retention days = %d, want 0", cfg.AuditRetentionDays)
	}
	t.Setenv(envAuditRetentionDays, "14")
	cfg, err = Load("--audit-retention-days=30")
	if err != nil {
		t.Fatalf("load overridden audit retention: %v", err)
	}
	if cfg.AuditRetentionDays != 30 {
		t.Fatalf("audit retention days = %d, want 30", cfg.AuditRetentionDays)
	}
}

func TestPwnedPasswordsEnabledDefaultEnvAndFlag(t *testing.T) {
	isolateLoadEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default HIBP setting: %v", err)
	}
	if cfg.PwnedPasswordsEnabled {
		t.Fatal("HIBP screening defaults to enabled, want false")
	}
	t.Setenv(envPwnedPasswordsEnabled, "true")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load HIBP environment setting: %v", err)
	}
	if !cfg.PwnedPasswordsEnabled {
		t.Fatal("HIBP environment setting = false, want true")
	}
	cfg, err = Load("--pwned-passwords-enabled=false")
	if err != nil {
		t.Fatalf("load HIBP flag override: %v", err)
	}
	if cfg.PwnedPasswordsEnabled {
		t.Fatal("HIBP flag override = true, want false")
	}
	t.Setenv(envPwnedPasswordsEnabled, "invalid")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid pwned-passwords enabled value") {
		t.Fatalf("Load() error = %v, want invalid HIBP toggle rejection", err)
	}
	cfg, err = Load("--pwned-passwords-enabled=true")
	if err != nil || !cfg.PwnedPasswordsEnabled {
		t.Fatalf("valid HIBP flag did not override invalid environment value: config=%+v err=%v", cfg, err)
	}
}

func TestRedactedPreservesHIBPToggle(t *testing.T) {
	if !((Config{PwnedPasswordsEnabled: true}).Redacted().PwnedPasswordsEnabled) {
		t.Fatal("redacted config hid the non-secret HIBP toggle")
	}
}

func TestLoadRejectsNegativeAuditRetentionDays(t *testing.T) {
	isolateLoadEnvironment(t)
	if _, err := Load("--audit-retention-days=-1"); err == nil || !strings.Contains(err.Error(), "audit retention days must not be negative") {
		t.Fatalf("Load() error = %v, want negative audit retention rejection", err)
	}
}

func TestLoadRequiresAuditForwardSecret(t *testing.T) {
	isolateLoadEnvironment(t)
	t.Setenv(envAuditForwardEndpoints, "https://audit.example.test/events")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "audit forwarding secret is required") {
		t.Fatalf("Load() error = %v, want missing audit forwarding secret rejection", err)
	}
}

func TestRedactedHidesAuditForwardingConfig(t *testing.T) {
	cfg := Config{
		AuditForwardEndpoints: []string{"https://audit.example.test/events"},
		AuditForwardSecret:   "shared secret",
	}
	redacted := cfg.Redacted()
	if len(redacted.AuditForwardEndpoints) != 0 || redacted.AuditForwardSecret != "[redacted]" {
		t.Fatalf("redacted audit forwarding config = %+v, want endpoints hidden and secret redacted", redacted)
	}
}
