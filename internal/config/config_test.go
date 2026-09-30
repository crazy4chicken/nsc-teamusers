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
		envLoginActivityRetentionDays, envAuditRetentionDays, envAuditForwardEndpoints, envAuditForwardSecret, envPwnedPasswordsEnabled,
		envRegistrationMode, envTokenAudience, envLockoutThreshold, envLockoutDuration,
		envAccessTokenTTL, envRefreshTokenTTL, envSessionFamilyTTL,
		envWebAuthnRPID, envWebAuthnOrigin, envTrustedProxies, envOIDCTrustUpstreamMFA, envOIDCMFAACRValues, "HOST", "PORT",
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

func TestLoginActivityRetentionDaysDefaultEnvironmentAndValidation(t *testing.T) {
	isolateLoadEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default login activity retention: %v", err)
	}
	if cfg.LoginActivityRetentionDays != DefaultLoginActivityRetentionDays {
		t.Fatalf("default login activity retention days = %d, want %d", cfg.LoginActivityRetentionDays, DefaultLoginActivityRetentionDays)
	}
	t.Setenv(envLoginActivityRetentionDays, "45")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load overridden login activity retention: %v", err)
	}
	if cfg.LoginActivityRetentionDays != 45 {
		t.Fatalf("login activity retention days = %d, want 45", cfg.LoginActivityRetentionDays)
	}
	t.Setenv(envLoginActivityRetentionDays, "-1")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "login activity retention days must not be negative") {
		t.Fatalf("Load() error = %v, want negative login activity retention rejection", err)
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
		AuditForwardEndpoints:      []string{"https://audit.example.test/events"},
		AuditForwardSecret:         "shared secret",
		LoginActivityRetentionDays: DefaultLoginActivityRetentionDays,
	}
	redacted := cfg.Redacted()
	if len(redacted.AuditForwardEndpoints) != 0 || redacted.AuditForwardSecret != "[redacted]" {
		t.Fatalf("redacted audit forwarding config = %+v, want endpoints hidden and secret redacted", redacted)
	}
	if redacted.LoginActivityRetentionDays != DefaultLoginActivityRetentionDays {
		t.Fatalf("redacted login activity retention days = %d, want %d", redacted.LoginActivityRetentionDays, DefaultLoginActivityRetentionDays)
	}
}

func TestOIDCUpstreamMFAConfig(t *testing.T) {
	isolateLoadEnvironment(t)
	cfg, err := Load()
	if err != nil {
		t.Fatalf("load default OIDC MFA config: %v", err)
	}
	if cfg.OIDCTrustUpstreamMFA || len(cfg.OIDCMFAACRValues) != 0 {
		t.Fatalf("default OIDC MFA config = trust:%v ACR:%v, want disabled trust and no ACR values", cfg.OIDCTrustUpstreamMFA, cfg.OIDCMFAACRValues)
	}

	t.Setenv(envOIDCTrustUpstreamMFA, "true")
	t.Setenv(envOIDCMFAACRValues, " urn:teamusers:mfa , urn:teamusers:step-up ")
	cfg, err = Load()
	if err != nil {
		t.Fatalf("load configured OIDC MFA policy: %v", err)
	}
	if !cfg.OIDCTrustUpstreamMFA || len(cfg.OIDCMFAACRValues) != 2 || cfg.OIDCMFAACRValues[0] != "urn:teamusers:mfa" || cfg.OIDCMFAACRValues[1] != "urn:teamusers:step-up" {
		t.Fatalf("loaded OIDC MFA config = trust:%v ACR:%v, want configured exact values", cfg.OIDCTrustUpstreamMFA, cfg.OIDCMFAACRValues)
	}
	redacted := cfg.Redacted()
	if !redacted.OIDCTrustUpstreamMFA || len(redacted.OIDCMFAACRValues) != 2 || redacted.OIDCMFAACRValues[0] != cfg.OIDCMFAACRValues[0] || redacted.OIDCMFAACRValues[1] != cfg.OIDCMFAACRValues[1] {
		t.Fatalf("redacted OIDC MFA config = trust:%v ACR:%v, want non-secret policy retained", redacted.OIDCTrustUpstreamMFA, redacted.OIDCMFAACRValues)
	}

	cfg, err = Load("--oidc-trust-upstream-mfa=false", "--oidc-mfa-acr-values=urn:teamusers:override")
	if err != nil || cfg.OIDCTrustUpstreamMFA || len(cfg.OIDCMFAACRValues) != 1 || cfg.OIDCMFAACRValues[0] != "urn:teamusers:override" {
		t.Fatalf("OIDC MFA flags did not override environment: trust:%v ACR:%v err=%v", cfg.OIDCTrustUpstreamMFA, cfg.OIDCMFAACRValues, err)
	}
}

func TestLoadRejectsInvalidOIDCUpstreamMFAConfig(t *testing.T) {
	isolateLoadEnvironment(t)
	t.Setenv(envOIDCTrustUpstreamMFA, "maybe")
	if _, err := Load(); err == nil || !strings.Contains(err.Error(), "invalid OIDC upstream MFA trust value") {
		t.Fatalf("Load() error = %v, want invalid OIDC upstream MFA trust rejection", err)
	}
	if cfg, err := Load("--oidc-trust-upstream-mfa=true"); err != nil || !cfg.OIDCTrustUpstreamMFA {
		t.Fatalf("valid OIDC MFA flag did not override invalid environment value: trust:%v err=%v", cfg.OIDCTrustUpstreamMFA, err)
	}
	t.Setenv(envOIDCMFAACRValues, "urn:teamusers:mfa,,urn:teamusers:step-up")
	if _, err := Load("--oidc-trust-upstream-mfa=false"); err == nil || !strings.Contains(err.Error(), "OIDC MFA ACR values must be non-empty") {
		t.Fatalf("Load() error = %v, want empty OIDC MFA ACR entry rejection", err)
	}
}
