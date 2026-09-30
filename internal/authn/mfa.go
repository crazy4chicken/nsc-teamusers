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
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	var request mfaLoginRequest
	if !decodeJSON(w, r, &request) {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, store.User{}, "", "mfa", "failure")
		writeUnauthorized(w, r)
		return
	}
	pending, err := s.parseMFAToken(strings.TrimSpace(request.MFAToken))
	if err != nil {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, store.User{}, "", "mfa", "failure")
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, pending.UserID)
	if err != nil || user.Status != "active" {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, "", "mfa", "failure")
		writeUnauthorized(w, r)
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, "", "mfa", "failure")
		s.auditAuth(r.Context(), s.q, "auth.login.mfa_locked", user, user.ID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}

	metadata := mfaCompletionMetadata(sessionMetadataFor(r, "user"), pending, "otp")
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
			response, consumeErr := s.consumeBackupAndComplete(r.Context(), user, backupDigest, metadata)
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
		response, err := s.completeMFALogin(r.Context(), user, metadata)
		if err != nil {
			writeInternal(w, r)
			return
		}
		writeJSON(w, http.StatusOK, response)
		return
	}
	s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, "", "mfa", "failure")
	if err := s.recordLoginFailure(r.Context(), user); err != nil {
		writeInternal(w, r)
		return
	}
	s.auditAuth(r.Context(), s.q, "auth.login.mfa_failed", user, user.ID)
	writeUnauthorized(w, r)
}

type pendingAuth struct {
	UserID   string   `json:"user_id"`
	AuthTime int64    `json:"auth_time"`
	AMR      []string `json:"amr"`
}

func (s *Service) signMFAToken(userID string, authTime int64, amr []string) (string, error) {
	return s.signPendingToken(userID, "mfa", authTime, amr)
}

func (s *Service) signMFAEnrollmentToken(userID string, authTime int64, amr []string) (string, error) {
	return s.signPendingToken(userID, "mfa_enroll", authTime, amr)
}

func (s *Service) signPendingToken(userID, purpose string, authTime int64, amr []string) (string, error) {
	if userID == "" || authTime <= 0 || len(amr) == 0 {
		return "", errors.New("invalid pending authentication claims")
	}
	now := s.now()
	token := jwt.New()
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	claims := map[string]any{
		"iss":       issuer,
		"aud":       audience,
		"sub":       userID,
		"purpose":   purpose,
		"iat":       now,
		"exp":       now.Add(mfaTokenTTL),
		"jti":       store.NewID(),
		"auth_time": authTime,
		"amr":       amr,
	}
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return "", err
		}
	}
	key, ok := s.activeSigningKey()
	if !ok {
		return "", errors.New("active signing key unavailable")
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, key.private))
	if err != nil {
		return "", err
	}
	return string(signed), nil
}

func (s *Service) parseMFAToken(raw string) (pendingAuth, error) {
	return s.parsePendingToken(raw, "mfa")
}

func (s *Service) parseMFAEnrollmentToken(raw string) (pendingAuth, error) {
	return s.parsePendingToken(raw, "mfa_enroll")
}

func (s *Service) parsePendingToken(raw, expectedPurpose string) (pendingAuth, error) {
	if raw == "" {
		return pendingAuth{}, errors.New("missing pending authentication token")
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(s.publicSet()), jwt.WithValidate(true))
	if err != nil {
		return pendingAuth{}, err
	}
	if token.Issuer() != issuer || token.Subject() == "" || token.Expiration().IsZero() || !token.Expiration().After(s.now()) {
		return pendingAuth{}, errors.New("invalid pending authentication token claims")
	}
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	audiences := token.Audience()
	if len(audiences) != 1 || audiences[0] != audience {
		return pendingAuth{}, errors.New("invalid pending authentication token audience")
	}
	purpose, ok := stringClaim(token, "purpose")
	if !ok || purpose != expectedPurpose {
		return pendingAuth{}, errors.New("invalid pending authentication token purpose")
	}
	var authTime int64
	if _, present := token.Get("auth_time"); present {
		var ok bool
		authTime, ok = int64Claim(token, "auth_time")
		if !ok {
			return pendingAuth{}, errors.New("invalid pending authentication time")
		}
	} else {
		issuedAt := token.IssuedAt()
		if issuedAt.IsZero() {
			return pendingAuth{}, errors.New("pending authentication time is missing")
		}
		authTime = issuedAt.Unix()
	}
	if authTime <= 0 {
		return pendingAuth{}, errors.New("invalid pending authentication time")
	}
	var amr []string
	if _, present := token.Get("amr"); present {
		var ok bool
		amr, ok = stringSliceClaim(token, "amr")
		if !ok {
			return pendingAuth{}, errors.New("invalid pending authentication methods")
		}
	} else {
		amr = []string{"pwd"}
	}
	if len(amr) == 0 {
		return pendingAuth{}, errors.New("pending authentication methods are missing")
	}
	primaryMethod := false
	for _, method := range amr {
		if method == "pwd" || method == "webauthn" {
			primaryMethod = true
		}
	}
	if !primaryMethod {
		return pendingAuth{}, errors.New("pending authentication lacks primary evidence")
	}
	return pendingAuth{UserID: token.Subject(), AuthTime: authTime, AMR: amr}, nil
}

func mfaCompletionMetadata(metadata sessionMetadata, pending pendingAuth, method string) sessionMetadata {
	metadata.AuthTime = pending.AuthTime
	metadata.AMR = append(append([]string(nil), pending.AMR...), method)
	return metadata
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
		if err := s.appendAuthAudit(txctx, q, "auth.login.succeeded", user.ID, user.ID); err != nil {
			return err
		}
		s.recordLoginActivityFromMetadata(txctx, q, user, "mfa", "success", metadata)
		return nil
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
		if err := s.appendAuthAudit(txctx, q, "auth.login.succeeded", user.ID, user.ID); err != nil {
			return err
		}
		s.recordLoginActivityFromMetadata(txctx, q, user, "mfa", "success", metadata)
		return nil
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
