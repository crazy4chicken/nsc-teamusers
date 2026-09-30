package passwd

import (
	"context"
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestPasswordInHistoryVerifiesArgon2idHashes(t *testing.T) {
	password := "HistoryVerificationPassword1"
	encoded, err := Hash(password)
	if err != nil {
		t.Fatalf("hash history password: %v", err)
	}
	otherHash, err := Hash("DifferentHistoryPassword2")
	if err != nil {
		t.Fatalf("hash different password: %v", err)
	}

	if !PasswordInHistory(password, []string{encoded}, "") {
		t.Fatal("password matching a stored history hash was not found")
	}
	if PasswordInHistory("UnrelatedPassword3", []string{encoded}, "") {
		t.Fatal("unrelated password matched stored history")
	}
	if !PasswordInHistory(password, nil, encoded) {
		t.Fatal("password matching the current credential hash was not found")
	}
	if PasswordInHistory("UnrelatedPassword3", nil, otherHash) {
		t.Fatal("unrelated password matched the current credential hash")
	}
}

func TestValidatePasswordFailsOpenWhenHIBPUnavailable(t *testing.T) {
	policy := Policy{MinLength: 1, BreachCheck: true}
	checker := func(context.Context, string) (bool, error) {
		return false, fmt.Errorf("offline")
	}
	if !validatePassword(context.Background(), policy, "acceptable", nil, "", true, checker) {
		t.Fatal("HIBP error rejected a password despite fail-open policy")
	}
}

func TestValidatePasswordScreensOnlyWhenEnabled(t *testing.T) {
	policy := Policy{MinLength: 1, BreachCheck: true}
	called := false
	checker := func(context.Context, string) (bool, error) {
		called = true
		return true, nil
	}
	if validatePassword(context.Background(), policy, "acceptable", nil, "", true, checker) {
		t.Fatal("known breached password was accepted")
	}
	if !called {
		t.Fatal("enabled breach policy did not call the checker")
	}
	called = false
	if !validatePassword(context.Background(), policy, "acceptable", nil, "", false, checker) {
		t.Fatal("disabled process setting rejected a password")
	}
	if called {
		t.Fatal("disabled process setting called the HIBP checker")
	}
}

func TestCheckPwnedPasswordUsesKAnonymityPrefix(t *testing.T) {
	password := "KAnonymityRangePassword1"
	digest := sha1.Sum([]byte(password))
	encoded := strings.ToUpper(hex.EncodeToString(digest[:]))
	prefix, suffix := encoded[:5], encoded[5:]

	for _, testCase := range []struct {
		name     string
		count    string
		breached bool
	}{
		{name: "breached suffix", count: "42", breached: true},
		{name: "padding suffix", count: "0", breached: false},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				if r.Method != http.MethodGet {
					t.Errorf("HIBP request method = %q, want GET", r.Method)
				}
				if r.URL.Path != "/range/"+prefix {
					t.Errorf("HIBP request path = %q, want only prefix %q", r.URL.Path, "/range/"+prefix)
				}
				if r.Header.Get("Add-Padding") != "true" {
					t.Errorf("Add-Padding header = %q, want true", r.Header.Get("Add-Padding"))
				}
				_, _ = fmt.Fprintf(w, "%s:%s\n", suffix, testCase.count)
			}))
			defer server.Close()

			found, err := checkPwnedPassword(context.Background(), password, server.Client(), server.URL+"/range")
			if err != nil {
				t.Fatalf("check HIBP range: %v", err)
			}
			if found != testCase.breached {
				t.Fatalf("breached = %t, want %t", found, testCase.breached)
			}
		})
	}
}
