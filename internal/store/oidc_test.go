package store

import (
	"strings"
	"testing"
)

func TestOIDCLockKeysEncodeComponentsUnambiguously(t *testing.T) {
	// These pairs collide if issuer and subject are joined with a NUL delimiter.
	subjectKeyA := oidcSubjectLockKey("issuer\x00part", "subject")
	subjectKeyB := oidcSubjectLockKey("issuer", "part\x00subject")
	if subjectKeyA == subjectKeyB {
		t.Fatal("distinct issuer/subject pairs produced the same lock key")
	}

	for _, key := range []string{
		subjectKeyA,
		subjectKeyB,
		oidcEmailLockKey("User\x00@Example.Test"),
	} {
		if strings.IndexByte(key, '\x00') >= 0 {
			t.Fatalf("lock key contains NUL: %q", key)
		}
	}

	if oidcSubjectLockKey("", "user@example.test") == oidcEmailLockKey("user@example.test") {
		t.Fatal("subject and email lock keys share a domain")
	}
	if oidcEmailLockKey("User@Example.Test") != oidcEmailLockKey("user@example.test") {
		t.Fatal("email lock keys do not case-fold the email")
	}
}
