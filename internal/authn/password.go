package authn

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"fmt"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	argonMemory     = 64 * 1024
	argonIterations = 3
	argonParallel   = 2
	argonSaltLength = 16
	argonKeyLength  = 32
)

// HashPassword returns an Argon2id PHC string using the OWASP-recommended
// memory, iteration, parallelism, salt, and derived-key parameters.
func HashPassword(password string) (string, error) {
	salt := make([]byte, argonSaltLength)
	if _, err := rand.Read(salt); err != nil {
		return "", fmt.Errorf("generate password salt: %w", err)
	}
	return encodePasswordHash(salt, argon2.IDKey([]byte(password), salt, argonIterations, argonMemory, argonParallel, argonKeyLength)), nil
}

// VerifyPassword checks an Argon2id PHC string without exposing parsing or
// password-match details to callers.
func VerifyPassword(encoded, password string) bool {
	salt, expected, memory, iterations, parallel, err := parsePasswordHash(encoded)
	if err != nil {
		return false
	}
	derived := argon2.IDKey([]byte(password), salt, iterations, memory, uint8(parallel), uint32(len(expected)))
	return subtle.ConstantTimeCompare(derived, expected) == 1
}

func newDummyPasswordHash() string {
	salt := []byte("nsc-tu-dummy-001")
	return encodePasswordHash(salt, argon2.IDKey([]byte("invalid-password"), salt, argonIterations, argonMemory, argonParallel, argonKeyLength))
}

func encodePasswordHash(salt, key []byte) string {
	encoding := base64.RawStdEncoding
	return fmt.Sprintf("$argon2id$v=19$m=%d,t=%d,p=%d$%s$%s",
		argonMemory, argonIterations, argonParallel,
		encoding.EncodeToString(salt), encoding.EncodeToString(key))
}

func parsePasswordHash(encoded string) (salt, key []byte, memory, iterations, parallel uint32, err error) {
	parts := strings.Split(encoded, "$")
	if len(parts) != 6 || parts[0] != "" || parts[1] != "argon2id" || parts[2] != "v=19" {
		return nil, nil, 0, 0, 0, errors.New("invalid Argon2id PHC string")
	}
	params := make(map[string]uint32, 3)
	for _, item := range strings.Split(parts[3], ",") {
		name, value, ok := strings.Cut(item, "=")
		if !ok || (name != "m" && name != "t" && name != "p") {
			return nil, nil, 0, 0, 0, errors.New("invalid Argon2id parameters")
		}
		parsed, parseErr := strconv.ParseUint(value, 10, 32)
		if parseErr != nil || parsed == 0 {
			return nil, nil, 0, 0, 0, errors.New("invalid Argon2id parameter value")
		}
		params[name] = uint32(parsed)
	}
	memory, iterations, parallel = params["m"], params["t"], params["p"]
	if memory < 16*1024 || iterations < 2 || parallel < 1 || memory > 1024*1024 || iterations > 20 || parallel > 32 {
		return nil, nil, 0, 0, 0, errors.New("Argon2id parameters out of bounds")
	}
	encoding := base64.RawStdEncoding
	salt, err = encoding.DecodeString(parts[4])
	if err != nil || len(salt) != argonSaltLength {
		return nil, nil, 0, 0, 0, errors.New("invalid Argon2id salt")
	}
	key, err = encoding.DecodeString(parts[5])
	if err != nil || len(key) != argonKeyLength {
		return nil, nil, 0, 0, 0, errors.New("invalid Argon2id key")
	}
	return salt, key, memory, iterations, parallel, nil
}

func passwordHashNeedsRehash(encoded string) bool {
	_, _, memory, iterations, parallel, err := parsePasswordHash(encoded)
	return err != nil || memory != argonMemory || iterations != argonIterations || parallel != argonParallel
}
