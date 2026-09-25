package authn

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"crypto/subtle"
	"encoding/base32"
	"errors"
	"fmt"
	"strings"
	"time"
)

const (
	totpSecretBytes = 20
	totpStep        = 30 * time.Second
	totpDigits      = 6
)

var totpEncoding = base32.StdEncoding.WithPadding(base32.NoPadding)

// GenerateSecret returns a random 160-bit secret encoded as unpadded base32.
func GenerateSecret() (string, error) {
	secret := make([]byte, totpSecretBytes)
	if _, err := rand.Read(secret); err != nil {
		return "", fmt.Errorf("generate TOTP secret: %w", err)
	}
	return totpEncoding.EncodeToString(secret), nil
}

// TOTPCode computes the six-digit RFC 6238 code for at. The secret is the
// unpadded base32 value returned by GenerateSecret.
func TOTPCode(secret string, at time.Time) (string, error) {
	key, err := decodeTOTPSecret(secret)
	if err != nil {
		return "", err
	}
	if at.Unix() < 0 {
		return "", errors.New("TOTP time must not be before the Unix epoch")
	}
	counter := uint64(at.Unix() / int64(totpStep/time.Second))
	var message [8]byte
	for index := len(message) - 1; index >= 0; index-- {
		message[index] = byte(counter)
		counter >>= 8
	}

	mac := hmac.New(sha1.New, key)
	_, _ = mac.Write(message[:])
	digest := mac.Sum(nil)
	offset := digest[len(digest)-1] & 0x0f
	value := (uint32(digest[offset])&0x7f)<<24 |
		(uint32(digest[offset+1]) << 16) |
		(uint32(digest[offset+2]) << 8) |
		uint32(digest[offset+3])
	return fmt.Sprintf("%0*d", totpDigits, value%1_000_000), nil
}

// ValidateCode accepts a TOTP code in the current, previous, or next 30-second
// time step. Every comparison uses a fixed six-byte representation and a
// constant-time comparison.
func ValidateCode(secret, code string, at time.Time) bool {
	if len(code) != totpDigits {
		return false
	}
	for index := 0; index < len(code); index++ {
		if code[index] < '0' || code[index] > '9' {
			return false
		}
	}

	valid := 0
	for _, offset := range []int{-1, 0, 1} {
		candidate, err := TOTPCode(secret, at.Add(time.Duration(offset)*totpStep))
		if err != nil {
			if offset < 0 {
				continue
			}
			return false
		}
		valid |= subtle.ConstantTimeCompare([]byte(candidate), []byte(code))
	}
	return valid == 1
}

func decodeTOTPSecret(secret string) ([]byte, error) {
	secret = strings.ToUpper(strings.TrimSpace(secret))
	if secret == "" {
		return nil, errors.New("TOTP secret must not be empty")
	}
	decoded, err := totpEncoding.DecodeString(secret)
	if err != nil {
		return nil, fmt.Errorf("decode TOTP secret: %w", err)
	}
	if len(decoded) != totpSecretBytes {
		return nil, fmt.Errorf("TOTP secret must be %d bytes", totpSecretBytes)
	}
	return decoded, nil
}
