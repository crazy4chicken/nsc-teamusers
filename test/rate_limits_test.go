package test

import (
	"context"
	"net/http"
	"testing"

	"teamusers/internal/config"
)

func TestRegistrationBurstRateLimit(t *testing.T) {
	stack := newIntegrationStackWithMode(t, "open")
	// Valid registrations are argon2-slow (~0.5-1s each), so a burst of them
	// never outruns the 30/min per-IP refill. Drain the bucket with cheap
	// malformed requests first (limiter counts every attempt regardless of
	// body validity), then prove a VALID registration is rejected.
	for attempt := range 30 {
		status, _ := stack.jsonRequest(t, http.MethodPost, "/auth/register", nil, "")
		if status != http.StatusBadRequest {
			t.Fatalf("registration drain attempt %d status = %d, want %d", attempt+1, status, http.StatusBadRequest)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/register", map[string]string{
		"username": "rate-register-blocked",
		"email":    "rate-register-blocked@example.test",
		"password": "RateRegisterPassword1",
	}, "")
	if status != http.StatusTooManyRequests {
		t.Fatalf("valid registration under drained limit status = %d, want %d: %s", status, http.StatusTooManyRequests, body)
	}
}

func TestLoginBurstRateLimit(t *testing.T) {
	stack := newIntegrationStackWithModeAndConfig(t, "closed", func(cfg *config.Config) {
		cfg.LockoutThreshold = 1
	})
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "rate-login-user", "RateLoginPassword1")
	for attempt := range 5 {
		status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
			"username": user.Username,
			"password": "wrong-password",
		}, "")
		wantStatus := http.StatusUnauthorized
		if attempt > 0 {
			wantStatus = http.StatusLocked
		}
		if status != wantStatus {
			t.Fatalf("login burst attempt %d status = %d, want %d: %s", attempt+1, status, wantStatus, body)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username,
		"password": "wrong-password",
	}, "")
	if status != http.StatusTooManyRequests {
		t.Fatalf("login burst limit status = %d, want %d: %s", status, http.StatusTooManyRequests, body)
	}
	var recordedFailures int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM login_activity
		WHERE user_id = $1 AND method = 'password' AND result = 'failure'`, user.ID).Scan(&recordedFailures); err != nil {
		t.Fatalf("count recorded login failures: %v", err)
	}
	if recordedFailures != 5 {
		t.Fatalf("recorded password failures = %d, want five authenticated attempts and no rate-limited row", recordedFailures)
	}
}

func TestMalformedLoginActivityRespectsIPRateLimit(t *testing.T) {
	stack := newIntegrationStack(t)
	for attempt := range 30 {
		status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", "not-an-object", "")
		if status != http.StatusUnauthorized {
			t.Fatalf("malformed login attempt %d status = %d, want %d: %s", attempt+1, status, http.StatusUnauthorized, body)
		}
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", "not-an-object", "")
	if status != http.StatusTooManyRequests {
		t.Fatalf("rate-limited malformed login status = %d, want %d: %s", status, http.StatusTooManyRequests, body)
	}
	var recordedFailures int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM login_activity
		WHERE user_id IS NULL AND method = 'password' AND result = 'failure'`).Scan(&recordedFailures); err != nil {
		t.Fatalf("count malformed login activity: %v", err)
	}
	if recordedFailures != 30 {
		t.Fatalf("malformed login activity rows = %d, want 30 limiter-passed attempts", recordedFailures)
	}
}
