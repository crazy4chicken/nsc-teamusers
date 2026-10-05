package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestMiddlewareRejectsMissingBearer(t *testing.T) {
	client := NewClient(nil, nil)
	handler := client.Middleware(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	}))
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRequireRejectsUnauthorizedPermission(t *testing.T) {
	permissions := NewPermissionsClient("http://127.0.0.1:1", WithServiceToken("svc"))
	client := NewClient(nil, permissions)
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	})
	handler := client.Require("order:read:team", nil)(next)
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	request = request.WithContext(WithClaims(context.Background(), Claims{
		Subject: "usr_1",
		Kind:    "user",
		Expiry:  time.Now().Add(time.Minute),
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusForbidden)
	}
}

func TestRequireFreshChecksAuthenticationEvidence(t *testing.T) {
	client := NewClient(nil, nil)
	now := time.Now()
	cases := []struct {
		name       string
		authTime   int64
		stepUpTime int64
		impersonated bool
		actor        string
		maxAge     time.Duration
		wantStatus int
	}{
		{name: "fresh", authTime: now.Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusOK},
		{name: "recent step-up", stepUpTime: now.Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusOK},
		{name: "step-up within configured age", stepUpTime: now.Add(-9 * time.Minute).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusOK},
		{name: "expired step-up", stepUpTime: now.Add(-11 * time.Minute).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "step-up future skew boundary", stepUpTime: now.Add(30 * time.Second).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusOK},
		{name: "step-up beyond future skew", stepUpTime: now.Add(31 * time.Second).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "impersonated step-up does not satisfy freshness", stepUpTime: now.Unix(), impersonated: true, maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "actor-only step-up does not satisfy freshness", stepUpTime: now.Unix(), actor: "admin_1", maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "fresh auth_time remains sufficient", authTime: now.Unix(), stepUpTime: now.Add(-11 * time.Minute).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusOK},
		{name: "missing", authTime: 0, maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "stale", authTime: now.Add(-11 * time.Minute).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "future skew boundary", authTime: now.Add(30 * time.Second).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusOK},
		{name: "beyond future skew", authTime: now.Add(31 * time.Second).Unix(), maxAge: 10 * time.Minute, wantStatus: http.StatusForbidden},
		{name: "invalid max age", authTime: now.Unix(), maxAge: 0, wantStatus: http.StatusForbidden},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := client.RequireFresh(tt.maxAge)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request = request.WithContext(WithClaims(context.Background(), Claims{AuthTime: tt.authTime, StepUpTime: tt.stepUpTime, Actor: tt.actor, Impersonated: tt.impersonated}))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tt.wantStatus {
				t.Fatalf("status = %d, want %d", response.Code, tt.wantStatus)
			}
			if called != (tt.wantStatus == http.StatusOK) {
				t.Fatalf("next called = %v, want %v", called, tt.wantStatus == http.StatusOK)
			}
			if tt.wantStatus == http.StatusForbidden && !strings.Contains(response.Body.String(), `"reason":"step_up_required"`) {
				t.Fatalf("response = %s, want step_up_required", response.Body.String())
			}
		})
	}
}


func TestAuthTimeIsFreshUsesInclusiveAgeAndFutureBoundaries(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	maxAge := 10 * time.Minute
	if !authTimeIsFresh(now.Add(-maxAge).Unix(), maxAge, now) {
		t.Fatal("timestamp at configured age boundary should be fresh")
	}
	if authTimeIsFresh(now.Add(-maxAge-time.Second).Unix(), maxAge, now) {
		t.Fatal("timestamp older than configured age should be stale")
	}
	if !authTimeIsFresh(now.Add(30*time.Second).Unix(), maxAge, now) {
		t.Fatal("timestamp at future skew boundary should be fresh")
	}
	if authTimeIsFresh(now.Add(31*time.Second).Unix(), maxAge, now) {
		t.Fatal("timestamp beyond future skew should be stale")
	}
}

func TestRequireFreshRejectsMissingClaims(t *testing.T) {
	client := NewClient(nil, nil)
	handler := client.RequireFresh(10 * time.Minute)(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}

func TestRejectImpersonatedBlocksOnlyImpersonatedClaims(t *testing.T) {
	client := NewClient(nil, nil)
	for _, tt := range []struct {
		name       string
		claims     Claims
		wantStatus int
		wantCalled bool
	}{
		{name: "ordinary", claims: Claims{Subject: "usr_1"}, wantStatus: http.StatusOK, wantCalled: true},
		{name: "impersonated", claims: Claims{Subject: "usr_1", Actor: "admin_1", Impersonated: true}, wantStatus: http.StatusForbidden},
	} {
		t.Run(tt.name, func(t *testing.T) {
			called := false
			handler := client.RejectImpersonated()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
				called = true
			}))
			request := httptest.NewRequest(http.MethodGet, "/", nil)
			request = request.WithContext(WithClaims(context.Background(), tt.claims))
			response := httptest.NewRecorder()
			handler.ServeHTTP(response, request)
			if response.Code != tt.wantStatus || called != tt.wantCalled {
				t.Fatalf("response = %d, handler called = %v, want status %d called %v", response.Code, called, tt.wantStatus, tt.wantCalled)
			}
			if tt.claims.Impersonated && !strings.Contains(response.Body.String(), `"reason":"impersonation_forbidden"`) {
				t.Fatalf("response = %s, want impersonation_forbidden", response.Body.String())
			}
		})
	}
}

func TestRejectImpersonatedRequiresClaims(t *testing.T) {
	client := NewClient(nil, nil)
	handler := client.RejectImpersonated()(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		t.Fatal("next handler should not run")
	}))
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/", nil))
	if response.Code != http.StatusUnauthorized {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusUnauthorized)
	}
}
