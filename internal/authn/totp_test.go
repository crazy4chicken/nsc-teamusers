package authn

import (
	"encoding/base32"
	"testing"
	"time"
)

func TestTOTPCodeRFC6238SHA1Vectors(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	vectors := []struct {
		unix int64
		want string
	}{
		{unix: 59, want: "287082"},
		{unix: 1111111109, want: "081804"},
		{unix: 1111111111, want: "050471"},
		{unix: 1234567890, want: "005924"},
		{unix: 2000000000, want: "279037"},
		{unix: 20000000000, want: "353130"},
	}
	for _, vector := range vectors {
		got, err := TOTPCode(secret, time.Unix(vector.unix, 0).UTC())
		if err != nil {
			t.Fatalf("TOTPCode(%d): %v", vector.unix, err)
		}
		if got != vector.want {
			t.Errorf("TOTPCode(%d) = %q, want %q", vector.unix, got, vector.want)
		}
	}
}

func TestValidateCodeAllowsAdjacentStepOnly(t *testing.T) {
	secret := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString([]byte("12345678901234567890"))
	at := time.Unix(1234567890, 0).UTC()
	code, err := TOTPCode(secret, at)
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateCode(secret, code, at.Add(29*time.Second)) {
		t.Fatal("code should be valid within the current time step")
	}
	previous, err := TOTPCode(secret, at.Add(-30*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if !ValidateCode(secret, previous, at) {
		t.Fatal("previous-step code should be valid")
	}
	future, err := TOTPCode(secret, at.Add(60*time.Second))
	if err != nil {
		t.Fatal(err)
	}
	if ValidateCode(secret, future, at) {
		t.Fatal("code two steps away should be invalid")
	}
	if ValidateCode(secret, "00000", at) || ValidateCode(secret, "abcdef", at) {
		t.Fatal("malformed codes should be invalid")
	}
}

func TestGenerateSecretIs160BitUnpaddedBase32(t *testing.T) {
	secret, err := GenerateSecret()
	if err != nil {
		t.Fatal(err)
	}
	if len(secret) != 32 {
		t.Fatalf("secret length = %d, want 32", len(secret))
	}
	if len(secret) > 0 && secret[len(secret)-1] == '=' {
		t.Fatal("secret must not use base32 padding")
	}
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		t.Fatal(err)
	}
	if len(decoded) != 20 {
		t.Fatalf("decoded secret length = %d, want 20", len(decoded))
	}
}
