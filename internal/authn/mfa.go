package authn

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"teamusers/internal/store"
)

const mfaTokenTTL = 5 * time.Minute

var errBackupCodeUsed = errors.New("backup code already used")

type mfaLoginRequest struct {
	MFAToken string `json:"mfa_token"`
	Code     string `json:"code"`
}

func (s *Service) recordLoginFailure(ctx context.Context, user store.User) error {
	_, err := store.IncrementFailedLogins(ctx, s.q, user.ID, s.cfg.LockoutThreshold, s.cfg.LockoutDuration)
	return err
}

func (s *Service) loginMFA(w http.ResponseWriter, r *http.Request) {
	var request mfaLoginRequest
	if !decodeJSON(w, r, &request) {
		writeUnauthorized(w, r)
		return
	}
	userID, err := s.parseMFAToken(strings.TrimSpace(request.MFAToken))
	if err != nil {
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, userID)
	if err != nil || user.Status != "active" {
		writeUnauthorized(w, r)
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
		s.auditAuth(r.Context(), s.q, "auth.login.mfa_locked", user, user.ID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}

	code := strings.TrimSpace(request.Code)
	valid := false
	if totp, err := store.GetCredential(r.Context(), s.q, user.ID, "totp"); err == nil {
		valid = ValidateCode(totp.Hash, code, s.now())
	} else if !errors.Is(err, pgx.ErrNoRows) {
		writeInternal(w, r)
		return
	}

	if !valid {
		if backupDigest, ok := backupCodeDigest(code); ok {
			response, consumeErr := s.consumeBackupAndComplete(r.Context(), user, backupDigest, sessionMetadataFor(r, "user"))
			if consumeErr == nil {
				writeJSON(w, http.StatusOK, response)
				return
			}
			if !errors.Is(consumeErr, errBackupCodeUsed) {
				writeInternal(w, r)
				return
			}
		}
	}

	if valid {
		response, err := s.completeMFALogin(r.Context(), user, sessionMetadataFor(r, "user"))
		if err != nil {
			writeInternal(w, r)
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	if err := s.recordLoginFailure(r.Context(), user); err != nil {
		writeInternal(w, r)
		return
	}
	s.auditAuth(r.Context(), s.q, "auth.login.mfa_failed", user, user.ID)
	writeUnauthorized(w, r)
}

func (s *Service) signMFAToken(userID string) (string, error) {
	now := s.now()
	token := jwt.New()
	claims := map[string]any{
		"iss":     issuer,
		"sub":     userID,
		"purpose": "mfa",
		"iat":     now,
		"exp":     now.Add(mfaTokenTTL),
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

func (s *Service) parseMFAToken(raw string) (string, error) {
	if raw == "" {
		return "", errors.New("missing MFA token")
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(s.publicSet()), jwt.WithValidate(true))
	if err != nil {
		return "", err
	}
	if token.Issuer() != issuer || token.Subject() == "" || token.Expiration().IsZero() || !token.Expiration().After(s.now()) {
		return "", errors.New("invalid MFA token claims")
	}
	purpose, ok := stringClaim(token, "purpose")
	if !ok || purpose != "mfa" {
		return "", errors.New("invalid MFA token purpose")
	}
	return token.Subject(), nil
}

func (s *Service) completeMFALogin(ctx context.Context, user store.User, metadata sessionMetadata) (tokenResponse, error) {
	var response tokenResponse
	issue := func(txctx context.Context, q store.Q) error {
		if err := store.ResetFailedLogins(txctx, q, user.ID); err != nil {
			return err
		}
		var err error
		response, err = s.issuePair(txctx, q, user, "user", "", time.Time{}, metadata)
		if err != nil {
			return err
		}
		return s.appendAuthAudit(txctx, q, "auth.login.succeeded", user.ID, user.ID)
	}
	if s.pool != nil {
		if err := store.WithTx(ctx, s.pool, func(txctx context.Context, tx store.Tx) error {
			return issue(txctx, tx)
		}); err != nil {
			return tokenResponse{}, err
		}
		return response, nil
	}
	if err := issue(ctx, s.q); err != nil {
		return tokenResponse{}, err
	}
	return response, nil
}

func (s *Service) consumeBackupAndComplete(ctx context.Context, user store.User, digest string, metadata sessionMetadata) (tokenResponse, error) {
	var response tokenResponse
	issue := func(txctx context.Context, q store.Q) error {
		consumed, err := store.ConsumeBackupCredential(txctx, q, user.ID, digest)
		if err != nil {
			return err
		}
		if !consumed {
			return errBackupCodeUsed
		}
		if err := store.ResetFailedLogins(txctx, q, user.ID); err != nil {
			return err
		}
		response, err = s.issuePair(txctx, q, user, "user", "", time.Time{}, metadata)
		if err != nil {
			return err
		}
		return s.appendAuthAudit(txctx, q, "auth.login.succeeded", user.ID, user.ID)
	}
	if s.pool != nil {
		if err := store.WithTx(ctx, s.pool, func(txctx context.Context, tx store.Tx) error {
			return issue(txctx, tx)
		}); err != nil {
			return tokenResponse{}, err
		}
		return response, nil
	}
	if err := issue(ctx, s.q); err != nil {
		return tokenResponse{}, err
	}
	return response, nil
}
