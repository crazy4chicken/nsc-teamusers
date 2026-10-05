package authn

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwt"

	"teamusers/internal/httpapi"
	"teamusers/internal/store"
)

const stepUpPurpose = "step_up"

var (
	errStepUpUnavailable    = errors.New("no enrolled MFA factor is available")
	errStepUpAccountLocked  = errors.New("step-up account is locked")
	errStepUpInvalidProof   = errors.New("invalid MFA step-up proof")
)

type stepUpBeginRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type stepUpBeginResponse struct {
	StepUpToken string         `json:"step_up_token"`
	Methods     []string       `json:"methods"`
	ExpiresIn   int64          `json:"expires_in"`
	PublicKey   map[string]any `json:"public_key,omitempty"`
}

type stepUpCompleteRequest struct {
	RefreshToken string          `json:"refresh_token"`
	StepUpToken  string          `json:"step_up_token"`
	Code         string          `json:"code,omitempty"`
	Credential   json.RawMessage `json:"credential,omitempty"`
}

type stepUpTokenClaims struct {
	UserID     string
	ChallengeID string
	SessionID  string
}

func (s *Service) beginStepUp(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || !stepUpSubjectEligible(subject) {
		writeAuthProblem(w, r, http.StatusForbidden, "step_up_forbidden")
		return
	}
	var request stepUpBeginRequest
	if !decodeJSON(w, r, &request) {
		writeStepUpBadRequest(w, r, "request body must be valid JSON")
		return
	}
	request.RefreshToken = strings.TrimSpace(request.RefreshToken)
	if request.RefreshToken == "" {
		writeStepUpBadRequest(w, r, "refresh_token is required")
		return
	}
	if s.pool == nil {
		writeInternal(w, r)
		return
	}

	expiresAt := s.now().Add(mfaTokenTTL)
	var user store.User
	var response stepUpBeginResponse
	err := store.WithTx(r.Context(), s.pool, func(ctx context.Context, tx store.Tx) error {
		session, policyUser, _, err := s.lockStepUpSession(ctx, tx, subject, request.RefreshToken)
		if err != nil {
			return err
		}
		user = policyUser
		if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
			return errStepUpAccountLocked
		}

		methods := make([]string, 0, 3)
		if _, err := store.GetCredential(ctx, tx, user.ID, "totp"); err == nil {
			methods = append(methods, "otp")
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}
		if backupCodes, err := store.GetCredential(ctx, tx, user.ID, "backup_codes"); err == nil {
			available, err := hasAvailableBackupCodes(backupCodes.Hash)
			if err != nil {
				return err
			}
			if available {
				methods = append(methods, "backup_code")
			}
		} else if !errors.Is(err, pgx.ErrNoRows) {
			return err
		}

		passkeys, err := store.GetPasskeys(ctx, tx, user.ID)
		if err != nil {
			return err
		}
		var publicKey map[string]any
		var webauthnSession json.RawMessage
		if len(passkeys) > 0 {
			assertion, sessionData, err := s.webAuthn.BeginLogin(passkeyUser{user: user, credentials: passkeys},
				webauthnlib.WithLoginOrigin(s.cfg.WebAuthnOrigin),
				webauthnlib.WithAllowedCredentials(webauthnlib.Credentials(passkeys).CredentialDescriptors()),
				webauthnlib.WithUserVerification(protocol.VerificationRequired),
			)
			if err != nil {
				return err
			}
			sessionData.Expires = expiresAt
			webauthnSession, err = json.Marshal(sessionData)
			if err != nil {
				return err
			}
			options, err := json.Marshal(assertion.Response)
			if err != nil {
				return err
			}
			if err := json.Unmarshal(options, &publicKey); err != nil {
				return err
			}
			if publicKey == nil {
				return errors.New("invalid WebAuthn assertion options")
			}
			publicKey["userVerification"] = "required"
			methods = append(methods, "webauthn")
		}
		if len(methods) == 0 {
			return errStepUpUnavailable
		}

		challengeID := store.NewID()
		stepUpToken, err := s.signStepUpToken(user.ID, challengeID, session.ID, expiresAt)
		if err != nil {
			return err
		}
		if err := store.DeleteExpiredStepUpChallenges(ctx, tx, s.now()); err != nil {
			return err
		}
		if err := store.CreateStepUpChallenge(ctx, tx, store.StepUpChallenge{
			ID: challengeID, UserID: user.ID, SessionID: session.ID, Purpose: stepUpPurpose,
			Methods: methods, WebauthnSession: webauthnSession, ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		if err := s.appendAuthAudit(ctx, tx, "auth.step_up.challenge_created", user.ID, user.ID); err != nil {
			return err
		}
		response = stepUpBeginResponse{
			StepUpToken: stepUpToken,
			Methods:     methods,
			ExpiresIn:   int64(mfaTokenTTL / time.Second),
			PublicKey:   publicKey,
		}
		return nil
	})
	if errors.Is(err, errInvalidRefresh) || errors.Is(err, errExpiredRefresh) {
		writeUnauthorized(w, r)
		return
	}
	if errors.Is(err, errStepUpAccountLocked) {
		s.auditAuth(r.Context(), s.q, "auth.step_up.locked", user, user.ID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	if errors.Is(err, errStepUpUnavailable) {
		writeAuthProblem(w, r, http.StatusForbidden, "step_up_not_available")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) completeStepUp(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || !stepUpSubjectEligible(subject) {
		writeAuthProblem(w, r, http.StatusForbidden, "step_up_forbidden")
		return
	}
	var request stepUpCompleteRequest
	if !decodeJSON(w, r, &request) {
		writeStepUpBadRequest(w, r, "request body must be valid JSON")
		return
	}
	request.RefreshToken = strings.TrimSpace(request.RefreshToken)
	request.StepUpToken = strings.TrimSpace(request.StepUpToken)
	request.Code = strings.TrimSpace(request.Code)
	credentialBody := bytes.TrimSpace(request.Credential)
	if request.RefreshToken == "" || request.StepUpToken == "" {
		writeStepUpBadRequest(w, r, "refresh_token and step_up_token are required")
		return
	}
	if (request.Code == "") == (len(credentialBody) == 0) {
		writeStepUpBadRequest(w, r, "exactly one of code or credential is required")
		return
	}
	stepUpClaims, err := s.parseStepUpToken(request.StepUpToken)
	if err != nil || stepUpClaims.UserID != subject.UserID {
		writeUnauthorized(w, r)
		return
	}

	var parsedCredential *protocol.ParsedCredentialAssertionData
	if len(credentialBody) > 0 {
		parsedCredential, err = protocol.ParseCredentialRequestResponseBytes(credentialBody)
		if err != nil || parsedCredential.Response.CollectedClientData.Challenge == "" {
			writePasskeyInvalid(w, r)
			return
		}
	}
	if s.pool == nil {
		writeInternal(w, r)
		return
	}

	var user store.User
	var response tokenResponse
	err = store.WithTx(r.Context(), s.pool, func(ctx context.Context, tx store.Tx) error {
		session, policyUser, policy, err := s.lockStepUpSession(ctx, tx, subject, request.RefreshToken)
		if err != nil {
			return err
		}
		user = policyUser
		if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
			return errStepUpAccountLocked
		}
		now := s.now()
		challenge, err := store.GetStepUpChallengeForUpdate(ctx, tx, stepUpClaims.ChallengeID)
		if errors.Is(err, pgx.ErrNoRows) {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		if challenge.Purpose != stepUpPurpose || challenge.UserID != user.ID || challenge.SessionID != session.ID ||
			stepUpClaims.SessionID != session.ID || !challenge.ExpiresAt.After(now) {
			return errInvalidRefresh
		}

		var (
			updatedPasskey         *webauthnlib.Credential
			webauthnSessionExpires time.Time
		)
		if request.Code != "" {
			valid, err := s.verifyStepUpCode(ctx, tx, user, challenge.Methods, request.Code)
			if err != nil {
				return err
			}
			if !valid {
				return errStepUpInvalidProof
			}
		} else {
			updatedPasskey, webauthnSessionExpires, err = s.verifyStepUpWebAuthn(ctx, tx, user, challenge, parsedCredential)
			if errors.Is(err, errStepUpInvalidProof) {
				return errStepUpInvalidProof
			}
			if err != nil {
				return err
			}
			if err := store.UpdatePasskey(ctx, tx, user.ID, *updatedPasskey); errors.Is(err, store.ErrNotFound) {
				return errStepUpInvalidProof
			} else if err != nil {
				return err
			}
		}

		completedAt := s.now()
		metadata := sessionMetadataFor(r, "user")
		storedMetadata := sessionMetadataFrom(session)
		metadata.AuthTime = storedMetadata.AuthTime
		metadata.authTimeMissing = metadata.AuthTime == 0
		metadata.StepUpTime = completedAt.Unix()
		metadata.AMR = append([]string(nil), storedMetadata.AMR...)
		if err := store.ResetFailedLogins(ctx, tx, user.ID); err != nil {
			return err
		}
		response, err = s.issuePairWithPolicy(ctx, tx, user, "user", session.FamilyID, session.FamilyNotAfter, session.ID, &policy, metadata)
		if err != nil {
			return err
		}
		if err := s.appendAuthAudit(ctx, tx, "auth.step_up.succeeded", user.ID, user.ID); err != nil {
			return err
		}
		s.recordLoginActivityFromMetadata(ctx, tx, user, "step_up", "success", metadata)
		if err := store.TouchSession(ctx, tx, session.ID, completedAt); err != nil {
			return err
		}
		if err := store.RevokeSession(ctx, tx, session.ID, "rotated"); err != nil {
			return err
		}
		finalNow := s.now()
		if !session.ExpiresAt.After(finalNow) || !session.FamilyNotAfter.After(finalNow) {
			return errExpiredRefresh
		}
		lastActiveAt := session.LastActiveAt
		if lastActiveAt.IsZero() {
			lastActiveAt = session.CreatedAt
		}
		if sessionIdleExpired(lastActiveAt, policy.IdleTimeoutMinutes, finalNow) {
			return errExpiredRefresh
		}
		if !webauthnSessionExpires.IsZero() && !webauthnSessionExpires.After(finalNow) {
			return errStepUpInvalidProof
		}
		if err := store.ConsumeStepUpChallenge(ctx, tx, challenge.ID, user.ID, session.ID, stepUpPurpose, finalNow); err != nil {
			return errInvalidRefresh
		}
		return nil
	})
	if err == nil {
		writeJSON(w, http.StatusOK, response)
		return
	}
	if errors.Is(err, errStepUpInvalidProof) {
		s.recordStepUpFailure(w, r, user)
		return
	}
	if errors.Is(err, errInvalidRefresh) || errors.Is(err, errExpiredRefresh) {
		writeUnauthorized(w, r)
		return
	}
	if errors.Is(err, errStepUpAccountLocked) {
		s.auditAuth(r.Context(), s.q, "auth.step_up.locked", user, user.ID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	writeInternal(w, r)
}

func (s *Service) lockStepUpSession(ctx context.Context, q store.Q, subject httpapi.Subject, rawRefresh string) (store.Session, store.User, store.SessionPolicy, error) {
	hash := refreshTokenHash(rawRefresh)
	sessionUserID, err := store.GetSessionUserID(ctx, q, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errInvalidRefresh
	}
	if err != nil {
		return store.Session{}, store.User{}, store.SessionPolicy{}, err
	}
	if sessionUserID != subject.UserID {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errInvalidRefresh
	}
	if err := store.LockSessionPolicyUser(ctx, q, sessionUserID); errors.Is(err, pgx.ErrNoRows) {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errInvalidRefresh
	} else if err != nil {
		return store.Session{}, store.User{}, store.SessionPolicy{}, err
	}
	session, err := store.GetSessionForUpdate(ctx, q, hash)
	if errors.Is(err, pgx.ErrNoRows) {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errInvalidRefresh
	}
	if err != nil {
		return store.Session{}, store.User{}, store.SessionPolicy{}, err
	}
	now := s.now()
	if session.UserID != subject.UserID || session.RevokedAt != nil || sessionKind(session) != "user" {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errInvalidRefresh
	}
	if session.FamilyID == "" || session.FamilyNotAfter.IsZero() ||
		!session.ExpiresAt.After(now) || !session.FamilyNotAfter.After(now) {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errExpiredRefresh
	}
	user, err := store.GetUser(ctx, q, session.UserID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (user.Status != "active" || user.PermVer != subject.PermVer)) {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errInvalidRefresh
	}
	if err != nil {
		return store.Session{}, store.User{}, store.SessionPolicy{}, err
	}
	policy, err := store.ResolveSessionPolicy(ctx, q, user.ID, now)
	if err != nil {
		return store.Session{}, store.User{}, store.SessionPolicy{}, err
	}
	lastActiveAt := session.LastActiveAt
	if lastActiveAt.IsZero() {
		lastActiveAt = session.CreatedAt
	}
	if sessionIdleExpired(lastActiveAt, policy.IdleTimeoutMinutes, now) {
		return store.Session{}, store.User{}, store.SessionPolicy{}, errExpiredRefresh
	}
	return session, user, policy, nil
}

func (s *Service) verifyStepUpCode(ctx context.Context, tx store.Tx, user store.User, methods []string, code string) (bool, error) {
	if hasStepUpMethod(methods, "otp") {
		totp, err := store.GetCredentialForUpdate(ctx, tx, user.ID, "totp")
		if err == nil && ValidateCode(totp.Hash, code, s.now()) {
			return true, nil
		}
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			return false, err
		}
	}
	if hasStepUpMethod(methods, "backup_code") {
		digest, ok := backupCodeDigest(code)
		if ok {
			consumed, err := store.ConsumeBackupCredential(ctx, tx, user.ID, digest)
			if err != nil {
				return false, err
			}
			return consumed, nil
		}
	}
	return false, nil
}

func (s *Service) verifyStepUpWebAuthn(ctx context.Context, tx store.Tx, user store.User, challenge store.StepUpChallenge, parsed *protocol.ParsedCredentialAssertionData) (*webauthnlib.Credential, time.Time, error) {
	if !hasStepUpMethod(challenge.Methods, "webauthn") || len(challenge.WebauthnSession) == 0 || parsed == nil {
		return nil, time.Time{}, errStepUpInvalidProof
	}
	var sessionData webauthnlib.SessionData
	if err := json.Unmarshal(challenge.WebauthnSession, &sessionData); err != nil {
		return nil, time.Time{}, err
	}
	challengeValue := parsed.Response.CollectedClientData.Challenge
	if sessionData.Challenge != challengeValue || !bytes.Equal(sessionData.UserID, []byte(user.ID)) {
		return nil, time.Time{}, errStepUpInvalidProof
	}
	credentials, err := store.GetPasskeysForUpdate(ctx, tx, user.ID)
	if err != nil {
		return nil, sessionData.Expires, err
	}
	if !sessionData.Expires.After(s.now()) || len(credentials) == 0 {
		return nil, sessionData.Expires, errStepUpInvalidProof
	}
	passkey := passkeyUser{user: user, credentials: credentials}
	credential, err := s.webAuthn.ValidateLogin(passkey, sessionData, parsed)
	if err != nil || credential == nil {
		return nil, sessionData.Expires, errStepUpInvalidProof
	}
	if !parsed.Response.AuthenticatorData.Flags.UserVerified() {
		return nil, sessionData.Expires, errStepUpInvalidProof
	}
	return credential, sessionData.Expires, nil
}

func (s *Service) signStepUpToken(userID, challengeID, sessionID string, expiresAt time.Time) (string, error) {
	if userID == "" || challengeID == "" || sessionID == "" || !expiresAt.After(s.now()) {
		return "", errors.New("invalid step-up challenge claims")
	}
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	token := jwt.New()
	claims := map[string]any{
		"iss":        issuer,
		"aud":        audience,
		"sub":        userID,
		"purpose":    stepUpPurpose,
		"iat":        s.now(),
		"exp":        expiresAt,
		"jti":        challengeID,
		"session_id": sessionID,
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

func (s *Service) parseStepUpToken(raw string) (stepUpTokenClaims, error) {
	if raw == "" {
		return stepUpTokenClaims{}, errors.New("missing step-up token")
	}
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(s.publicSet()), jwt.WithValidate(true))
	if err != nil {
		return stepUpTokenClaims{}, err
	}
	if token.Issuer() != issuer || token.Subject() == "" || token.Expiration().IsZero() || !token.Expiration().After(s.now()) {
		return stepUpTokenClaims{}, errors.New("invalid step-up token claims")
	}
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	audiences := token.Audience()
	if len(audiences) != 1 || audiences[0] != audience {
		return stepUpTokenClaims{}, errors.New("invalid step-up token audience")
	}
	purpose, ok := stringClaim(token, "purpose")
	if !ok || purpose != stepUpPurpose {
		return stepUpTokenClaims{}, errors.New("invalid step-up token purpose")
	}
	challengeID, ok := stringClaim(token, "jti")
	if !ok || challengeID == "" {
		return stepUpTokenClaims{}, errors.New("invalid step-up token challenge ID")
	}
	sessionID, ok := stringClaim(token, "session_id")
	if !ok || sessionID == "" {
		return stepUpTokenClaims{}, errors.New("invalid step-up token session ID")
	}
	return stepUpTokenClaims{UserID: token.Subject(), ChallengeID: challengeID, SessionID: sessionID}, nil
}

func stepUpSubjectEligible(subject httpapi.Subject) bool {
	return subject.UserID != "" && subject.Kind == "user" && !subject.Impersonated && subject.ActorID == ""
}

func hasAvailableBackupCodes(encoded string) (bool, error) {
	var digests []string
	if err := json.Unmarshal([]byte(encoded), &digests); err != nil {
		return false, err
	}
	return len(digests) > 0, nil
}


func hasStepUpMethod(methods []string, method string) bool {
	for _, available := range methods {
		if available == method {
			return true
		}
	}
	return false
}

func (s *Service) recordStepUpFailure(w http.ResponseWriter, r *http.Request, user store.User) {
	s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, "", "step_up", "failure")
	locked, err := store.IncrementFailedLogins(r.Context(), s.q, user.ID, s.cfg.LockoutThreshold, s.cfg.LockoutDuration)
	if err != nil {
		writeInternal(w, r)
		return
	}
	if locked {
		s.auditAuth(r.Context(), s.q, "auth.step_up.locked", user, user.ID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	s.auditAuth(r.Context(), s.q, "auth.step_up.failed", user, user.ID)
	writeUnauthorized(w, r)
}

func writeStepUpBadRequest(w http.ResponseWriter, r *http.Request, detail string) {
	httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", detail)
}
