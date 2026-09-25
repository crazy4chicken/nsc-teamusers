package authn

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/protocol"
	webauthnlib "github.com/go-webauthn/webauthn/webauthn"

	"teamusers/internal/config"
	"teamusers/internal/httpapi"
	"teamusers/internal/store"
)

const webauthnChallengeTTL = 5 * time.Minute

var (
	errPasskeyLocked   = errors.New("passkey account is locked")
	errPasskeyInactive = errors.New("passkey account is inactive")
)

type passkeyUser struct {
	user        store.User
	credentials []webauthnlib.Credential
}

func (u passkeyUser) WebAuthnID() []byte {
	return []byte(u.user.ID)
}

func (u passkeyUser) WebAuthnName() string {
	return u.user.Username
}

func (u passkeyUser) WebAuthnDisplayName() string {
	if u.user.DisplayName != "" {
		return u.user.DisplayName
	}
	return u.user.Username
}

func (u passkeyUser) WebAuthnCredentials() []webauthnlib.Credential {
	return u.credentials
}

func newWebAuthn(cfg config.Config) (*webauthnlib.WebAuthn, error) {
	return webauthnlib.New(&webauthnlib.Config{
		RPID:                   cfg.WebAuthnRPID,
		RPDisplayName:          "teamusers",
		RPOrigins:              []string{cfg.WebAuthnOrigin},
		AttestationPreference:  protocol.PreferNoAttestation,
		AuthenticatorSelection: webauthnlib.SelectAuthenticator("", protocol.ResidentKeyRequired(), "preferred"),
	})
}

func (s *Service) passkeyUser(ctx context.Context, user store.User) (passkeyUser, error) {
	credentials, err := store.GetPasskeys(ctx, s.q, user.ID)
	if err != nil {
		return passkeyUser{}, err
	}
	return passkeyUser{user: user, credentials: credentials}, nil
}

func (s *Service) beginPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	passkey, err := s.passkeyUser(r.Context(), user)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	creation, session, err := s.webAuthn.BeginRegistration(passkey,
		webauthnlib.WithRegistrationOrigin(s.cfg.WebAuthnOrigin),
		webauthnlib.WithExclusions(webauthnlib.Credentials(passkey.credentials).CredentialDescriptors()),
	)
	if err != nil {
		writeInternal(w, r)
		return
	}
	session.Expires = s.now().Add(webauthnChallengeTTL)
	sessionData, err := json.Marshal(session)
	if err != nil {
		writeInternal(w, r)
		return
	}
	userID := user.ID
	if _, err := store.CreateWebauthnChallenge(r.Context(), s.q, store.WebauthnChallenge{
		UserID:      &userID,
		Kind:        "register",
		Challenge:   session.Challenge,
		SessionData: sessionData,
		ExpiresAt:   session.Expires,
	}); err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, creation)
}

func (s *Service) finishPasskeyRegistration(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	body, ok := readPasskeyBody(w, r)
	if !ok {
		writePasskeyInvalid(w, r)
		return
	}
	parsed, err := protocol.ParseCredentialCreationResponseBytes(body)
	if err != nil || parsed.Response.CollectedClientData.Challenge == "" {
		writePasskeyInvalid(w, r)
		return
	}
	challenge := parsed.Response.CollectedClientData.Challenge
	rawSession, err := store.ConsumeWebauthnChallenge(r.Context(), s.q, challenge, "register")
	if errors.Is(err, store.ErrNotFound) {
		writePasskeyInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	var session webauthnlib.SessionData
	if err := json.Unmarshal(rawSession, &session); err != nil {
		writeInternal(w, r)
		return
	}
	if session.Challenge != challenge || !bytes.Equal(session.UserID, []byte(subject.UserID)) {
		writePasskeyInvalid(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	passkey, err := s.passkeyUser(r.Context(), user)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	credential, err := s.webAuthn.CreateCredential(passkey, session, parsed)
	if err != nil {
		writePasskeyInvalid(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		if err := store.AddPasskey(ctx, tx, user.ID, *credential); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "auth.passkey.registered", user.ID, user.ID)
	})
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type passkeyLoginBeginRequest struct {
	Username string `json:"username"`
}

func (s *Service) beginPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	var request passkeyLoginBeginRequest
	body, ok := readPasskeyBody(w, r)
	if !ok {
		writeUnauthorized(w, r)
		return
	}
	if len(bytes.TrimSpace(body)) != 0 {
		if err := json.Unmarshal(body, &request); err != nil {
			writeUnauthorized(w, r)
			return
		}
	}
	username := strings.TrimSpace(request.Username)
	if username == "" {
		if !s.limiter.allowIP(requestIP(r), s.now()) {
			writeRateLimited(w, r)
			return
		}
		assertion, session, err := s.webAuthn.BeginDiscoverableLogin(
			webauthnlib.WithLoginOrigin(s.cfg.WebAuthnOrigin),
		)
		if err != nil {
			writeInternal(w, r)
			return
		}
		s.storePasskeyLoginChallenge(w, r, assertion, session, nil)
		return
	}
	if !s.limiter.allow(requestIP(r), username, s.now()) {
		writeRateLimited(w, r)
		return
	}
	user, err := store.GetUserByUsername(r.Context(), s.q, username)
	if err != nil || user.Status != "active" {
		writeUnauthorized(w, r)
		return
	}
	if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
		s.auditAuth(r.Context(), s.q, "auth.passkey.login.locked", user, username)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	passkey, err := s.passkeyUser(r.Context(), user)
	if err != nil || len(passkey.credentials) == 0 {
		writeUnauthorized(w, r)
		return
	}
	assertion, session, err := s.webAuthn.BeginLogin(passkey,
		webauthnlib.WithLoginOrigin(s.cfg.WebAuthnOrigin),
		webauthnlib.WithAllowedCredentials(webauthnlib.Credentials(passkey.credentials).CredentialDescriptors()),
	)
	if err != nil {
		writeInternal(w, r)
		return
	}
	s.storePasskeyLoginChallenge(w, r, assertion, session, &user.ID)
}

func (s *Service) storePasskeyLoginChallenge(w http.ResponseWriter, r *http.Request, assertion *protocol.CredentialAssertion, session *webauthnlib.SessionData, userID *string) {
	session.Expires = s.now().Add(webauthnChallengeTTL)
	sessionData, err := json.Marshal(session)
	if err != nil {
		writeInternal(w, r)
		return
	}
	if _, err := store.CreateWebauthnChallenge(r.Context(), s.q, store.WebauthnChallenge{
		UserID:      userID,
		Kind:        "login",
		Challenge:   session.Challenge,
		SessionData: sessionData,
		ExpiresAt:   session.Expires,
	}); err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, assertion)
}

func (s *Service) finishPasskeyLogin(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	body, ok := readPasskeyBody(w, r)
	if !ok {
		writePasskeyInvalid(w, r)
		return
	}
	parsed, err := protocol.ParseCredentialRequestResponseBytes(body)
	if err != nil || parsed.Response.CollectedClientData.Challenge == "" {
		writePasskeyInvalid(w, r)
		return
	}
	challenge := parsed.Response.CollectedClientData.Challenge
	rawSession, err := store.ConsumeWebauthnChallenge(r.Context(), s.q, challenge, "login")
	if errors.Is(err, store.ErrNotFound) {
		writePasskeyInvalid(w, r)
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	var session webauthnlib.SessionData
	if err := json.Unmarshal(rawSession, &session); err != nil {
		writeInternal(w, r)
		return
	}
	if session.Challenge != challenge {
		writePasskeyInvalid(w, r)
		return
	}

	var resolvedUser store.User
	var credential *webauthnlib.Credential
	if len(session.UserID) != 0 {
		resolvedUser, err = store.GetUser(r.Context(), s.q, string(session.UserID))
		if err != nil {
			writeUnauthorized(w, r)
			return
		}
		if resolvedUser.LockedUntil != nil && resolvedUser.LockedUntil.After(s.now()) {
			s.auditAuth(r.Context(), s.q, "auth.passkey.login.locked", resolvedUser, resolvedUser.Username)
			writeAuthProblem(w, r, http.StatusLocked, "account_locked")
			return
		}
		if resolvedUser.Status != "active" {
			writeUnauthorized(w, r)
			return
		}
		passkey, passkeyErr := s.passkeyUser(r.Context(), resolvedUser)
		if passkeyErr != nil {
			writeUnauthorized(w, r)
			return
		}
		credential, err = s.webAuthn.ValidateLogin(passkey, session, parsed)
	} else {
		_, foundCredential, finishErr := s.webAuthn.ValidatePasskeyLogin(func(rawID, _ []byte) (webauthnlib.User, error) {
			user, lookupErr := store.GetUserByPasskeyCredID(r.Context(), s.q, rawID)
			if lookupErr != nil {
				return nil, lookupErr
			}
			resolvedUser = user
			if user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
				return nil, errPasskeyLocked
			}
			if user.Status != "active" {
				return nil, errPasskeyInactive
			}
			passkey, passkeyErr := s.passkeyUser(r.Context(), user)
			if passkeyErr != nil {
				return nil, passkeyErr
			}
			return passkey, nil
		}, session, parsed)
		credential = foundCredential
		err = finishErr
	}
	if err != nil {
		if resolvedUser.ID != "" && resolvedUser.LockedUntil != nil && resolvedUser.LockedUntil.After(s.now()) {
			s.auditAuth(r.Context(), s.q, "auth.passkey.login.locked", resolvedUser, resolvedUser.Username)
			writeAuthProblem(w, r, http.StatusLocked, "account_locked")
			return
		}
		if resolvedUser.ID != "" && resolvedUser.Status == "active" {
			locked, failureErr := s.recordPasskeyFailure(r.Context(), resolvedUser)
			if failureErr != nil {
				writeInternal(w, r)
				return
			}
			if locked {
				s.auditAuth(r.Context(), s.q, "auth.passkey.login.locked", resolvedUser, resolvedUser.Username)
				writeAuthProblem(w, r, http.StatusLocked, "account_locked")
				return
			}
		}
		s.auditAuth(r.Context(), s.q, "auth.passkey.login.failed", resolvedUser, "passkey")
		writeUnauthorized(w, r)
		return
	}
	if credential == nil || resolvedUser.ID == "" {
		writeUnauthorized(w, r)
		return
	}
	if resolvedUser.LockedUntil != nil && resolvedUser.LockedUntil.After(s.now()) {
		s.auditAuth(r.Context(), s.q, "auth.passkey.login.locked", resolvedUser, resolvedUser.Username)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	if resolvedUser.Status != "active" {
		writeUnauthorized(w, r)
		return
	}
	response, err := s.completePasskeyLogin(r.Context(), resolvedUser, *credential, sessionMetadataFor(r, "user"))
	if err != nil {
		writeInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) recordPasskeyFailure(ctx context.Context, user store.User) (bool, error) {
	return store.IncrementFailedLogins(ctx, s.q, user.ID, s.cfg.LockoutThreshold, s.cfg.LockoutDuration)
}

func (s *Service) completePasskeyLogin(ctx context.Context, user store.User, credential webauthnlib.Credential, metadata sessionMetadata) (tokenResponse, error) {
	var response tokenResponse
	issue := func(txctx context.Context, q store.Q) error {
		if err := store.UpdatePasskey(txctx, q, user.ID, credential); err != nil {
			return err
		}
		if err := store.ResetFailedLogins(txctx, q, user.ID); err != nil {
			return err
		}
		var err error
		response, err = s.issuePair(txctx, q, user, "user", "", time.Time{}, metadata)
		if err != nil {
			return err
		}
		return s.appendAuthAudit(txctx, q, "auth.passkey.login.succeeded", user.ID, user.ID)
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

type passkeyResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) listPasskeys(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	credentials, err := store.GetPasskeys(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	createdAt := time.Time{}
	if len(credentials) > 0 {
		row, rowErr := store.GetCredential(r.Context(), s.q, subject.UserID, store.PasskeyCredentialKind)
		if rowErr != nil {
			httpapi.WriteStoreProblem(w, r, rowErr)
			return
		}
		createdAt = row.CreatedAt
	}
	response := make([]passkeyResponse, 0, len(credentials))
	for _, credential := range credentials {
		response = append(response, passkeyResponse{
			ID:        base64.RawURLEncoding.EncodeToString(credential.ID),
			CreatedAt: createdAt,
		})
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) deletePasskey(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	credentialID, ok := decodePasskeyID(chi.URLParam(r, "credID"))
	if !ok {
		writePasskeyNotFound(w, r)
		return
	}
	var deleted int64
	err := store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		var err error
		deleted, err = store.DeletePasskey(ctx, tx, subject.UserID, credentialID)
		if err != nil {
			return err
		}
		if deleted == 0 {
			return store.ErrNotFound
		}
		return s.appendAuthAudit(ctx, tx, "auth.passkey.deleted", subject.UserID, subject.UserID)
	})
	if errors.Is(err, store.ErrNotFound) {
		writePasskeyNotFound(w, r)
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func decodePasskeyID(raw string) ([]byte, bool) {
	decoded, err := base64.RawURLEncoding.DecodeString(raw)
	if err == nil && len(decoded) > 0 {
		return decoded, true
	}
	decoded, err = base64.URLEncoding.DecodeString(raw)
	return decoded, err == nil && len(decoded) > 0
}

func readPasskeyBody(w http.ResponseWriter, r *http.Request) ([]byte, bool) {
	body, err := io.ReadAll(http.MaxBytesReader(w, r.Body, 1<<20))
	return body, err == nil
}

func writePasskeyInvalid(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "invalid WebAuthn response")
}

func writePasskeyNotFound(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteProblem(w, r, http.StatusNotFound, "Not Found", "the requested passkey was not found")
}
