package main

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"unicode/utf8"

	"teamusers/internal/passwd"
)

func TestGenerateTemporaryPasswordMinLengths(t *testing.T) {
	for _, minLength := range []int{1, 24, 1024} {
		t.Run(strconv.Itoa(minLength), func(t *testing.T) {
			policy := passwd.Policy{MinLength: minLength}
			password, err := generateTemporaryPassword(context.Background(), policy)
			if err != nil {
				t.Fatalf("generateTemporaryPassword() error = %v", err)
			}

			wantLength := minLength
			if wantLength < 24 {
				wantLength = 24
			}
			if gotLength := utf8.RuneCountInString(password); gotLength != wantLength {
				t.Fatalf("password length = %d, want %d", gotLength, wantLength)
			}
			if !policy.Validate(password) {
				t.Fatalf("generated password does not satisfy policy")
			}
		})
	}
}

func TestGenerateTemporaryPasswordAllClasses(t *testing.T) {
	policy := passwd.Policy{
		MinLength:     24,
		RequireLetter: true,
		RequireUpper:  true,
		RequireLower:  true,
		RequireDigit:  true,
		RequireSymbol: true,
	}
	password, err := generateTemporaryPassword(context.Background(), policy)
	if err != nil {
		t.Fatalf("generateTemporaryPassword() error = %v", err)
	}
	if !policy.Validate(password) {
		t.Fatalf("generated password does not satisfy all character classes")
	}
}

func TestGenerateTemporaryPasswordCanceledContext(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	_, err := generateTemporaryPassword(ctx, passwd.Policy{MinLength: 24})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("generateTemporaryPassword() error = %v, want %v", err, context.Canceled)
	}
}
