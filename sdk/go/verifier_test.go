package iam

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"
)

func TestVerifierValidatesAccessTokenClaims(t *testing.T) {
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate verifier key: %v", err)
	}
	privateKey, err := jwk.FromRaw(private)
	if err != nil {
		t.Fatalf("create private verifier key: %v", err)
	}
	publicKey, err := jwk.FromRaw(private.Public())
	if err != nil {
		t.Fatalf("create public verifier key: %v", err)
	}
	for _, key := range []jwk.Key{privateKey, publicKey} {
		if err := key.Set(jwk.KeyIDKey, "sdk-test"); err != nil {
			t.Fatalf("set verifier key id: %v", err)
		}
		if err := key.Set(jwk.AlgorithmKey, jwa.EdDSA); err != nil {
			t.Fatalf("set verifier key algorithm: %v", err)
		}
	}
	keys := jwk.NewSet()
	if err := keys.AddKey(publicKey); err != nil {
		t.Fatalf("add verifier public key: %v", err)
	}
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/jwk-set+json")
		_ = json.NewEncoder(w).Encode(keys)
	}))
	defer server.Close()
	verifier := NewVerifier(server.URL, WithJWKSMinRefreshInterval(time.Hour))
	defer verifier.Close()

	now := time.Now().UTC()
	valid := signSDKTestToken(t, privateKey, map[string]any{
		"iss": "teamusers", "aud": "teamusers", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
		"auth_time": now.Add(-time.Minute).Unix(), "amr": []string{"pwd", "otp"},
		"iat": now, "exp": now.Add(5 * time.Minute),
	})
	claims, err := verifier.Verify(t.Context(), valid)
	if err != nil {
		t.Fatalf("verify valid SDK token: %v", err)
	}
	if claims.Subject != "sdk-user" || claims.Kind != "user" || claims.PermVer != 2 || claims.Audience != "teamusers" ||
		claims.AuthTime != now.Add(-time.Minute).Unix() || len(claims.AMR) != 2 || claims.AMR[0] != "pwd" || claims.AMR[1] != "otp" {
		t.Fatalf("verified SDK claims = %+v", claims)
	}

	legacy := signSDKTestToken(t, privateKey, map[string]any{
		"iss": "teamusers", "aud": "teamusers", "sub": "legacy-user", "kind": "user", "perm_ver": int64(2),
		"iat": now, "exp": now.Add(5 * time.Minute),
	})
	legacyClaims, err := verifier.Verify(t.Context(), legacy)
	if err != nil {
		t.Fatalf("verify legacy SDK token: %v", err)
	}
	if legacyClaims.AuthTime != 0 || len(legacyClaims.AMR) != 0 {
		t.Fatalf("legacy SDK claims = %+v, want absent authentication evidence", legacyClaims)
	}

	cases := []struct {
		name  string
		token string
	}{
		{
			name: "wrong issuer",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "other", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
				"iat": now, "exp": now.Add(5 * time.Minute),
			}),
		},
		{
			name: "wrong audience",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "teamusers", "aud": "other", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
				"iat": now, "exp": now.Add(5 * time.Minute),
			}),
		},
		{
			name: "missing audience",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "teamusers", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
				"iat": now, "exp": now.Add(5 * time.Minute),
			}),
		},
		{
			name: "expired",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "teamusers", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
				"iat": now.Add(-2 * time.Minute), "exp": now.Add(-time.Minute),
			}),
		},
		{
			name: "missing kind",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "teamusers", "sub": "sdk-user", "perm_ver": int64(2),
				"iat": now, "exp": now.Add(5 * time.Minute),
			}),
		},
		{
			name:  "tampered signature",
			token: tamperSDKSignature(t, valid),
		},
		{
			name:  "wrong algorithm",
			token: replaceSDKAlgorithm(t, valid, "RS256"),
		},
		{
			name: "invalid auth_time",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "teamusers", "aud": "teamusers", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
				"auth_time": int64(-1), "iat": now, "exp": now.Add(5 * time.Minute),
			}),
		},
		{
			name: "invalid amr",
			token: signSDKTestToken(t, privateKey, map[string]any{
				"iss": "teamusers", "aud": "teamusers", "sub": "sdk-user", "kind": "user", "perm_ver": int64(2),
				"amr": "pwd", "iat": now, "exp": now.Add(5 * time.Minute),
			}),
		},
	}
	for _, tt := range cases {
		t.Run(tt.name, func(t *testing.T) {
			if _, err := verifier.Verify(t.Context(), tt.token); err == nil {
				t.Fatalf("Verify accepted %s token", tt.name)
			}
		})
	}
}

func signSDKTestToken(t *testing.T, key jwk.Key, claims map[string]any) string {
	t.Helper()
	token := jwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			t.Fatalf("set SDK JWT claim %q: %v", name, err)
		}
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, key))
	if err != nil {
		t.Fatalf("sign SDK JWT: %v", err)
	}
	return string(signed)
}

func tamperSDKSignature(t *testing.T, raw string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatalf("decode SDK JWT signature: %v", err)
	}
	signature[0] ^= 1
	parts[2] = base64.RawURLEncoding.EncodeToString(signature)
	return strings.Join(parts, ".")
}

func replaceSDKAlgorithm(t *testing.T, raw, algorithm string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode SDK JWT header: %v", err)
	}
	var values map[string]any
	if err := json.Unmarshal(header, &values); err != nil {
		t.Fatalf("decode SDK JWT header JSON: %v", err)
	}
	values["alg"] = algorithm
	header, err = json.Marshal(values)
	if err != nil {
		t.Fatalf("encode SDK JWT header JSON: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(header)
	return strings.Join(parts, ".")
}
