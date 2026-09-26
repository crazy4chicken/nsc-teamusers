package passwd

import (
	"strings"
	"testing"
)

func TestHashVerifyRoundTrip(t *testing.T) {
	const password = "correct horse battery staple"

	encoded, err := Hash(password)
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if !Verify(encoded, password) {
		t.Fatal("Verify() rejected the password used to create the hash")
	}
	if Verify(encoded, "wrong password") {
		t.Fatal("Verify() accepted a wrong password")
	}
}

func TestNeedsRehashDetectsParameterDrift(t *testing.T) {
	encoded, err := Hash("correct horse battery staple")
	if err != nil {
		t.Fatalf("Hash() error = %v", err)
	}
	if NeedsRehash(encoded) {
		t.Fatal("NeedsRehash() reported a current hash as stale")
	}

	drifted := strings.Replace(encoded, "m=65536,", "m=32768,", 1)
	if drifted == encoded {
		t.Fatal("test fixture did not change the memory parameter")
	}
	if !NeedsRehash(drifted) {
		t.Fatal("NeedsRehash() accepted a hash with drifted parameters")
	}
}

func TestNewDummyHashHasValidFormat(t *testing.T) {
	encoded := NewDummyHash()
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" || parts[3] != "m=65536,t=3,p=2" {
		t.Fatalf("NewDummyHash() = %q, want an Argon2id PHC string", encoded)
	}
	if len(parts[4]) != 22 || len(parts[5]) != 43 {
		t.Fatalf("NewDummyHash() salt/key lengths = %d/%d, want 22/43", len(parts[4]), len(parts[5]))
	}
	if !Verify(encoded, "invalid-password") {
		t.Fatal("NewDummyHash() did not produce a verifiable Argon2id hash")
	}
}
