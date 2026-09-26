package authn

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"teamusers/internal/store"
)

func TestParseAccessTokenClaims(t *testing.T) {
	now := time.Now().UTC()
	service := newJWTTestService(t, now)

	tests := []struct {
		name    string
		mutate  func(string) string
		wantErr bool
	}{
		{name: "expired", mutate: func(raw string) string {
			return signJWTClaims(t, service, map[string]any{
				"iss": "teamusers", "sub": "user-1", "kind": "user", "perm_ver": int64(1),
				"iat": now.Add(-2 * time.Minute), "exp": now.Add(-time.Minute),
			})
		}, wantErr: true},
		{name: "wrong issuer", mutate: func(raw string) string {
			return signJWTClaims(t, service, map[string]any{
				"iss": "other-service", "sub": "user-1", "kind": "user", "perm_ver": int64(1),
				"iat": now, "exp": now.Add(time.Minute),
			})
		}, wantErr: true},
		{name: "wrong audience", mutate: func(raw string) string {
			return signJWTClaims(t, service, map[string]any{
				"iss": "teamusers", "aud": "other-service", "sub": "user-1", "kind": "user", "perm_ver": int64(1),
				"iat": now, "exp": now.Add(time.Minute),
			})
		}, wantErr: true},
		{name: "missing audience", mutate: func(raw string) string {
			return signJWTClaims(t, service, map[string]any{
				"iss": "teamusers", "sub": "user-1", "kind": "user", "perm_ver": int64(1),
				"iat": now, "exp": now.Add(time.Minute),
			})
		}, wantErr: true},
		{name: "wrong algorithm", mutate: func(raw string) string {
			return replaceJWTHeaderAlgorithm(t, raw, "RS256")
		}, wantErr: true},
		{name: "tampered signature", mutate: func(raw string) string {
			parts := strings.Split(raw, ".")
			signature, err := base64.RawURLEncoding.DecodeString(parts[2])
			if err != nil {
				t.Fatalf("decode access signature: %v", err)
			}
			signature[0] ^= 1
			parts[2] = base64.RawURLEncoding.EncodeToString(signature)
			return strings.Join(parts, ".")
		}, wantErr: true},
		{name: "missing kind", mutate: func(raw string) string {
			return signJWTClaims(t, service, map[string]any{
				"iss": "teamusers", "sub": "user-1", "perm_ver": int64(1),
				"iat": now, "exp": now.Add(time.Minute),
			})
		}, wantErr: true},
	}

	valid, err := service.signAccessToken(store.User{ID: "user-1", PermVer: 1}, "", "user")
	if err != nil {
		t.Fatalf("sign valid access token: %v", err)
	}
	if claims, err := service.parseAccessToken(valid); err != nil {
		t.Fatalf("parse valid access token: %v", err)
	} else if claims.Subject != "user-1" || claims.Kind != "user" || claims.PermVer != 1 {
		t.Fatalf("valid access claims = %+v", claims)
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			raw := valid
			if tt.mutate != nil {
				raw = tt.mutate(raw)
			}
			_, err := service.parseAccessToken(raw)
			if (err != nil) != tt.wantErr {
				t.Fatalf("parseAccessToken() error = %v, want error %v", err, tt.wantErr)
			}
		})
	}
}

func TestParseAccessTokenAcceptsUserAndServiceKinds(t *testing.T) {
	now := time.Now().UTC()
	service := newJWTTestService(t, now)
	for _, kind := range []string{"user", "service"} {
		raw, err := service.signAccessToken(store.User{ID: "kind-user", PermVer: 4}, "", kind)
		if err != nil {
			t.Fatalf("sign %s access token: %v", kind, err)
		}
		claims, err := service.parseAccessToken(raw)
		if err != nil {
			t.Fatalf("parse %s access token: %v", kind, err)
		}
		if claims.Kind != kind {
			t.Fatalf("parsed kind = %q, want %q", claims.Kind, kind)
		}
	}
}

func TestMFAAndAccessTokenPurposesDoNotCrossAuthenticate(t *testing.T) {
	now := time.Now().UTC()
	service := newJWTTestService(t, now)
	mfaToken, err := service.signMFAToken("purpose-user")
	if err != nil {
		t.Fatalf("sign MFA token: %v", err)
	}
	if _, err := service.parseAccessToken(mfaToken); err == nil {
		t.Fatal("MFA token was accepted as an access token")
	}
	accessToken, err := service.signAccessToken(store.User{ID: "purpose-user", PermVer: 0}, "", "user")
	if err != nil {
		t.Fatalf("sign access token: %v", err)
	}
	if _, err := service.parseMFAToken(accessToken); err == nil {
		t.Fatal("access token was accepted as an MFA token")
	}
}

func TestParseMFATokenAudience(t *testing.T) {
	now := time.Now().UTC()
	service := newJWTTestService(t, now)
	valid, err := service.signMFAToken("mfa-user")
	if err != nil {
		t.Fatalf("sign valid MFA token: %v", err)
	}
	if userID, err := service.parseMFAToken(valid); err != nil || userID != "mfa-user" {
		t.Fatalf("parse valid MFA token = %q, %v", userID, err)
	}
	key := service.keys[service.activeKid]
	for _, tt := range []struct {
		name string
		aud  any
	}{
		{name: "wrong audience", aud: "other-service"},
		{name: "missing audience", aud: nil},
	} {
		t.Run(tt.name, func(t *testing.T) {
			claims := map[string]any{
				"iss": issuer, "sub": "mfa-user", "purpose": "mfa",
				"iat": now, "exp": now.Add(time.Minute),
			}
			if tt.aud != nil {
				claims["aud"] = tt.aud
			}
			token := jwt.New()
			for name, value := range claims {
				if err := token.Set(name, value); err != nil {
					t.Fatalf("set MFA claim %q: %v", name, err)
				}
			}
			raw, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, key.private))
			if err != nil {
				t.Fatalf("sign MFA token: %v", err)
			}
			if _, err := service.parseMFAToken(string(raw)); err == nil {
				t.Fatalf("parseMFAToken accepted %s token", tt.name)
			}
		})
	}
}

func newJWTTestService(t *testing.T, now time.Time) *Service {
	t.Helper()
	_, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("generate JWT test key: %v", err)
	}
	key, err := makeSigningKey("jwt-test", private)
	if err != nil {
		t.Fatalf("create JWT test key: %v", err)
	}
	return &Service{
		keys:      map[string]signingKey{key.kid: key},
		activeKid: key.kid,
		now:       func() time.Time { return now },
	}
}

func signJWTClaims(t *testing.T, service *Service, claims map[string]any) string {
	t.Helper()
	token := jwt.New()
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			t.Fatalf("set JWT claim %q: %v", name, err)
		}
	}
	key := service.keys[service.activeKid]
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, key.private))
	if err != nil {
		t.Fatalf("sign JWT claims: %v", err)
	}
	return string(signed)
}

func replaceJWTHeaderAlgorithm(t *testing.T, raw, algorithm string) string {
	t.Helper()
	parts := strings.Split(raw, ".")
	if len(parts) != 3 {
		t.Fatalf("JWT has %d parts, want 3", len(parts))
	}
	header, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		t.Fatalf("decode JWT header: %v", err)
	}
	var values map[string]any
	if err := json.Unmarshal(header, &values); err != nil {
		t.Fatalf("decode JWT header JSON: %v", err)
	}
	values["alg"] = algorithm
	header, err = json.Marshal(values)
	if err != nil {
		t.Fatalf("encode JWT header JSON: %v", err)
	}
	parts[0] = base64.RawURLEncoding.EncodeToString(header)
	return strings.Join(parts, ".")
}
