package authn

import (
	"errors"
	"strings"
	"time"

	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"teamusers/internal/store"
)

const passwordChangeTokenTTL = 10 * time.Minute

func (s *Service) signPasswordChangeToken(userID string) (string, error) {
	now := s.now()
	token := jwt.New()
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	claims := map[string]interface{}{
		"iss":     issuer,
		"sub":     userID,
		"purpose": "password_change",
		"aud":     audience,
		"iat":     now,
		"exp":     now.Add(passwordChangeTokenTTL),
		"jti":     store.NewID(),
	}
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return "", err
		}
	}
	key, ok := s.keys[s.activeKid]
	if !ok {
		return "", errors.New("active signing key unavailable")
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, key.private))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func (s *Service) parsePasswordChangeToken(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("missing password-change token")
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(s.publicSet()), jwt.WithValidate(true))
	if err != nil {
		return "", err
	}
	if token.Issuer() != issuer || token.Subject() == "" || token.Expiration().IsZero() || !token.Expiration().After(s.now()) {
		return "", errors.New("invalid password-change token claims")
	}
	purpose, ok := stringClaim(token, "purpose")
	if !ok || purpose != "password_change" {
		return "", errors.New("invalid password-change token purpose")
	}
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	audiences := token.Audience()
	if len(audiences) != 1 || audiences[0] != audience {
		return "", errors.New("invalid password-change token audience")
	}
	return token.Subject(), nil
}
