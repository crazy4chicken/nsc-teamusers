package test

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"testing"

	"github.com/fxamacker/cbor/v2"
)

func TestPasskeyHTTPPaths(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "passkey-http", "passkey-password")
	accessToken := loginUser(t, stack, user.Username, "passkey-password")

	status, body := stack.jsonRequest(t, http.MethodPost, "/me/passkeys/register/begin", map[string]any{}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("register begin status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var begin struct {
		PublicKey struct {
			Challenge   string `json:"challenge"`
			Attestation string `json:"attestation"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &begin)
	if begin.PublicKey.Challenge == "" || begin.PublicKey.Attestation != "none" {
		t.Fatalf("register options = %+v, want challenge and none attestation", begin.PublicKey)
	}

	status, _ = stack.rawRequest(t, http.MethodPost, "/me/passkeys/register/finish", []byte(`{"garbage":true}`), accessToken, map[string]string{
		"Content-Type": "application/json",
	})
	if status != http.StatusBadRequest && status != http.StatusUnauthorized {
		t.Fatalf("garbage register finish status = %d, want 400 or 401", status)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me/passkeys", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("empty passkey list status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var passkeys []struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &passkeys)
	if len(passkeys) != 0 {
		t.Fatalf("empty passkey list = %+v", passkeys)
	}

	status, _ = stack.jsonRequest(t, http.MethodDelete, "/me/passkeys/AQ", nil, accessToken)
	if status != http.StatusNotFound {
		t.Fatalf("unknown passkey delete status = %d, want %d", status, http.StatusNotFound)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", map[string]string{
		"username": "does-not-exist",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown passkey login begin status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	if len(body) == 0 || bytes.Contains(body, []byte("does-not-exist")) {
		t.Fatalf("unknown passkey login response leaked username: %s", body)
	}
}

func TestPasskeyCeremonyWithSoftAuthenticator(t *testing.T) {
	stack := newIntegrationStack(t)
	user := seedPasswordUser(t, context.Background(), stack.database.pool, "passkey-ceremony", "passkey-password")
	accessToken := loginUser(t, stack, user.Username, "passkey-password")
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate soft authenticator key: %v", err)
	}
	credentialID := make([]byte, 32)
	if _, err := rand.Read(credentialID); err != nil {
		t.Fatalf("generate soft authenticator credential id: %v", err)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/me/passkeys/register/begin", map[string]any{}, accessToken)
	if status != http.StatusOK {
		t.Fatalf("register begin status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var creation struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &creation)
	if creation.PublicKey.Challenge == "" {
		t.Fatal("register begin returned an empty challenge")
	}
	registerClientData := clientDataJSON("webauthn.create", creation.PublicKey.Challenge, "http://localhost")
	registerAuthenticatorData := registrationAuthenticatorData("localhost", credentialID, privateKey.PublicKey)
	attestationObject, err := cbor.Marshal(map[string]any{
		"fmt":      "none",
		"attStmt":  map[string]any{},
		"authData": registerAuthenticatorData,
	})
	if err != nil {
		t.Fatalf("encode soft authenticator attestation: %v", err)
	}
	registerResponse := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(registerClientData),
			"attestationObject": base64.RawURLEncoding.EncodeToString(attestationObject),
		},
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/passkeys/register/finish", registerResponse, accessToken)
	if status != http.StatusNoContent {
		t.Fatalf("register finish status = %d, want %d: %s", status, http.StatusNoContent, body)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me/passkeys", nil, accessToken)
	if status != http.StatusOK {
		t.Fatalf("passkey list status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var passkeys []struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &passkeys)
	if len(passkeys) != 1 || passkeys[0].ID != base64.RawURLEncoding.EncodeToString(credentialID) {
		t.Fatalf("passkey list = %+v, want credential %s", passkeys, base64.RawURLEncoding.EncodeToString(credentialID))
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/begin", map[string]string{
		"username": user.Username,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login begin status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var assertion struct {
		PublicKey struct {
			Challenge string `json:"challenge"`
		} `json:"publicKey"`
	}
	decodeResponse(t, body, &assertion)
	if assertion.PublicKey.Challenge == "" {
		t.Fatal("login begin returned an empty challenge")
	}
	loginClientData := clientDataJSON("webauthn.get", assertion.PublicKey.Challenge, "http://localhost")
	loginAuthenticatorData := assertionAuthenticatorData("localhost", 1)
	clientDataHash := sha256.Sum256(loginClientData)
	signedData := append(append([]byte(nil), loginAuthenticatorData...), clientDataHash[:]...)
	assertionHash := sha256.Sum256(signedData)
	signature, err := ecdsa.SignASN1(rand.Reader, privateKey, assertionHash[:])
	if err != nil {
		t.Fatalf("sign soft authenticator assertion: %v", err)
	}
	loginResponse := map[string]any{
		"id":    base64.RawURLEncoding.EncodeToString(credentialID),
		"rawId": base64.RawURLEncoding.EncodeToString(credentialID),
		"type":  "public-key",
		"response": map[string]string{
			"clientDataJSON":    base64.RawURLEncoding.EncodeToString(loginClientData),
			"authenticatorData": base64.RawURLEncoding.EncodeToString(loginAuthenticatorData),
			"signature":         base64.RawURLEncoding.EncodeToString(signature),
			"userHandle":        base64.RawURLEncoding.EncodeToString([]byte(user.ID)),
		},
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/passkey/login/finish", loginResponse, "")
	if status != http.StatusOK {
		t.Fatalf("login finish status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
}

func clientDataJSON(kind, challenge, origin string) []byte {
	body, _ := json.Marshal(map[string]string{
		"type":      kind,
		"challenge": challenge,
		"origin":    origin,
	})
	return body
}

func registrationAuthenticatorData(rpid string, credentialID []byte, publicKey ecdsa.PublicKey) []byte {
	rpIDHash := sha256.Sum256([]byte(rpid))
	data := make([]byte, 0, 128)
	data = append(data, rpIDHash[:]...)
	data = append(data, 0x41, 0, 0, 0, 0)
	data = append(data, make([]byte, 16)...)
	data = append(data, byte(len(credentialID)>>8), byte(len(credentialID)))
	data = append(data, credentialID...)
	coseKey, _ := cbor.Marshal(map[int]any{
		1:  int64(2),
		3:  int64(-7),
		-1: int64(1),
		-2: paddedBytes(publicKey.X, 32),
		-3: paddedBytes(publicKey.Y, 32),
	})
	return append(data, coseKey...)
}

func assertionAuthenticatorData(rpid string, counter uint32) []byte {
	rpIDHash := sha256.Sum256([]byte(rpid))
	return append(rpIDHash[:], 0x01, byte(counter>>24), byte(counter>>16), byte(counter>>8), byte(counter))
}

func paddedBytes(value *big.Int, size int) []byte {
	encoded := value.Bytes()
	result := make([]byte, size)
	copy(result[size-len(encoded):], encoded)
	return result
}
