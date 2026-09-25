package test

import (
	"net/http"
	"testing"
)

func TestHealthAndReadiness(t *testing.T) {
	stack := newIntegrationStack(t)

	status, body := stack.jsonRequest(t, http.MethodGet, "/healthz", nil, "")
	if status != http.StatusOK {
		t.Fatalf("health status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var health struct {
		Status string `json:"status"`
	}
	decodeResponse(t, body, &health)
	if health.Status != "ok" {
		t.Fatalf("health response = %+v, want status ok", health)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/readyz", nil, "")
	if status != http.StatusOK {
		t.Fatalf("readiness status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var readiness struct {
		Status string `json:"status"`
	}
	decodeResponse(t, body, &readiness)
	if readiness.Status != "ready" {
		t.Fatalf("readiness response = %+v, want status ready", readiness)
	}
}
