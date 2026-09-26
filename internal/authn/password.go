package authn

import (
	"teamusers/internal/config"
	"teamusers/internal/passwd"
)

// HashPassword returns an Argon2id PHC string using the OWASP-recommended
// memory, iteration, parallelism, salt, and derived-key parameters.
func HashPassword(password string) (string, error) {
	return passwd.Hash(password)
}

// VerifyPassword checks an Argon2id PHC string without exposing parsing or
// password-match details to callers.
func VerifyPassword(encoded, password string) bool {
	return passwd.Verify(encoded, password)
}

func newDummyPasswordHash() string {
	return passwd.NewDummyHash()
}

func passwordHashNeedsRehash(encoded string) bool {
	return passwd.NeedsRehash(encoded)
}

// ValidatePassword applies the configured minimum length and alphanumeric
// character-class requirements.
func ValidatePassword(password string, minLength int) bool {
	return config.ValidatePassword(password, minLength)
}
