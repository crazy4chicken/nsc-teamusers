package iam

import (
	"context"
	"net/http"
	"net/http/httptest"
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
