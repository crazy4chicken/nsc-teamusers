package authn

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/mail"
	"strings"
	"sync"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-webauthn/webauthn/webauthn"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/config"
	"teamusers/internal/httpapi"
	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

const (
	issuer           = "teamusers"
	refreshTokenSize = 32
)

var (
	errInvalidRefresh = errors.New("invalid refresh token")
	errExpiredRefresh = errors.New("expired refresh token")
)

// Deps contains the configuration and database handles required by Service.
type Deps struct {
	Config  config.Config
	Q       store.Q
	Pool    *pgxpool.Pool
	Audit   *auditlog.Writer
	Context context.Context
}

// Dependencies is an explicit alias for callers that prefer the longer name.
type Dependencies = Deps

// Service owns password authentication, signing keys, and refresh-token
// sessions.
type Service struct {
	cfg             config.Config
	q               store.Q
	pool            *pgxpool.Pool
	keyMu           sync.RWMutex
	rotationMu      sync.Mutex
	pendingRotation *preparedSigningKeyRotation
	keys            map[string]signingKey
	activeKid       string
	limiter         *loginLimiter
	dummyHash       string
	audit           *auditlog.Writer
	webAuthn        *webauthn.WebAuthn
	now             func() time.Time
	oidcMu sync.Mutex
	oidc   *oidcProvider
}

func New(deps Deps) (*Service, error) {
	deps.Config = deps.Config.WithDefaults()
	if err := deps.Config.Validate(); err != nil {
		return nil, err
	}
	if deps.Q == nil && deps.Pool == nil {
		return nil, errors.New("authn query handle must not be nil")
	}
	q := deps.Q
	if q == nil {
		q = deps.Pool
	}
	pool := deps.Pool
	if pool == nil {
		pool, _ = q.(*pgxpool.Pool)
	}
	keys, activeKid, err := loadSigningKeys(deps.Config.KeyDir, deps.Config.AccessTokenTTL)
	if err != nil {
		return nil, err
	}
	webAuthn, err := newWebAuthn(deps.Config)
	if err != nil {
		return nil, err
	}
	if deps.Audit == nil {
		deps.Audit = auditlog.NewWriter()
	}
	service := &Service{
		cfg:       deps.Config,
		q:         q,
		pool:      pool,
		keys:      keys,
		activeKid: activeKid,
		limiter:   newLoginLimiter(),
		dummyHash: newDummyPasswordHash(),
		audit:     deps.Audit,
		webAuthn:  webAuthn,
		now:       time.Now,
	}
	if pool != nil {
		ctx := deps.Context
		if ctx == nil {
			ctx = context.Background()
		}
		go service.reapExpiredSessions(ctx)
	}
	return service, nil
}

// Routes returns the public authentication, registration, and JWKS routes.
func (s *Service) Routes() chi.Router {
	router := chi.NewRouter()
	router.Post("/auth/login", s.login)
	router.Get("/auth/oidc/begin", s.oidcBegin)
	router.Get("/auth/oidc/callback", s.oidcCallback)
	router.Post("/auth/register", s.register)
	router.Post("/auth/verify-email", s.verifyEmail)
	router.Post("/auth/invite/accept", s.acceptInvitation)
	router.Post("/auth/password-reset/request", s.requestPasswordReset)
	router.Post("/auth/password-reset/confirm", s.confirmPasswordReset)
	router.Post("/auth/client-credentials", s.clientCredentials)
	router.Post("/auth/login/mfa", s.loginMFA)
	router.Post("/auth/login/mfa/enroll/begin", s.beginMFATOTPEnrollment)
	router.Post("/auth/login/mfa/enroll/complete", s.completeMFATOTPEnrollment)
	router.Post("/auth/passkey/login/begin", s.beginPasskeyLogin)
	router.Post("/auth/passkey/login/finish", s.finishPasskeyLogin)
	router.Post("/auth/refresh", s.refresh)
	router.Post("/auth/logout", s.logout)
	router.Post("/auth/introspect", s.introspect)
	router.Get("/.well-known/jwks.json", s.jwks)
	return router
}

// Middleware verifies an access JWT, checks that its subject remains active,
// and injects the HTTP API subject used by the admin plane. POST /me/password
// and GET /me/password-policy also accept password_change tokens.
func (s *Service) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if (r.Method == http.MethodPost && r.URL.Path == "/me/password") ||
				(r.Method == http.MethodGet && r.URL.Path == "/me/password-policy") {
				if raw, ok := bearerToken(r.Header.Get("Authorization")); ok {
					if userID, err := s.parsePasswordChangeToken(raw); err == nil {
						user, err := store.GetUser(r.Context(), s.q, userID)
						if err == nil && user.Status == "active" {
							subject := httpapi.Subject{UserID: user.ID, Kind: "user", PermVer: user.PermVer}
							next.ServeHTTP(w, r.WithContext(httpapi.ContextWithSubject(r.Context(), subject)))
							return
						}
					}
				}
			}
			claims, _, err := s.authenticateBearer(r, "")
			if err != nil {
				writeUnauthorized(w, r)
				return
			}
			subject := httpapi.Subject{
				UserID: claims.Subject, TeamID: claims.Team, Kind: claims.Kind, PermVer: claims.PermVer,
				AuthTime: claims.AuthTime, AMR: append([]string(nil), claims.AMR...),
				Impersonated: claims.Impersonated, ActorID: claims.ActorID,
			}
			next.ServeHTTP(w, r.WithContext(httpapi.ContextWithSubject(r.Context(), subject)))
		})
	}
}

func (s *Service) authenticateBearer(r *http.Request, requiredKind string) (tokenClaims, store.User, error) {
	raw, ok := bearerToken(r.Header.Get("Authorization"))
	if !ok {
		return tokenClaims{}, store.User{}, errors.New("missing bearer token")
	}
	claims, err := s.parseAccessToken(raw)
	if err != nil {
		return tokenClaims{}, store.User{}, err
	}
	if requiredKind != "" && claims.Kind != requiredKind {
		return tokenClaims{}, store.User{}, errors.New("unexpected access token kind")
	}
	user, err := store.GetUser(r.Context(), s.q, claims.Subject)
	if err != nil || user.Status != "active" || user.PermVer != claims.PermVer {
		return tokenClaims{}, store.User{}, errors.New("stale or inactive access token")
	}
	return claims, user, nil
}

type loginRequest struct {
	Username string `json:"username"`
	Password string `json:"password"`
}

type registerRequest struct {
	Username    string `json:"username"`
	Email       string `json:"email"`
	Password    string `json:"password"`
	DisplayName string `json:"display_name,omitempty"`
}

type verifyEmailRequest struct {
	Token string `json:"token"`
}

type passwordResetRequest struct {
	Login string `json:"login"`
}

type passwordResetConfirmRequest struct {
	Token       string `json:"token"`
	NewPassword string `json:"new_password"`
}

type inviteAcceptRequest struct {
	Token       string  `json:"token"`
	Password    string  `json:"password"`
	DisplayName *string `json:"display_name,omitempty"`
}

func (s *Service) register(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	if s.registrationMode() == "closed" {
		writeAuthProblem(w, r, http.StatusForbidden, "registration_closed")
		return
	}
	var request registerRequest
	if !decodeJSON(w, r, &request) {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "request body must be valid JSON")
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.TrimSpace(request.Email)
	if request.Username == "" {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "username is required")
		return
	}
	parsedEmail, err := mail.ParseAddress(request.Email)
	if err != nil || parsedEmail.Address != request.Email {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "email must be a valid address")
		return
	}
	userID := store.NewID()
	checked, err := passwd.CheckSet(r.Context(), s.q, userID, request.Password, s.cfg.PwnedPasswordsEnabled, s.now())
	if errors.Is(err, passwd.ErrPolicyRejected) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}

	plaintextToken, tokenHash, err := newVerificationToken()
	if err != nil {
		writeInternal(w, r)
		return
	}
	expiresAt := s.now().Add(24 * time.Hour)
	var created store.User
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		created, err = store.CreateUser(ctx, tx, store.User{
			ID:          userID,
			Username:    request.Username,
			Email:       &request.Email,
			DisplayName: request.DisplayName,
			Status:      "pending",
		})
		if err != nil {
			return err
		}
		if err := passwd.RecordSet(ctx, tx, checked); err != nil {
			return err
		}
		if _, err := store.CreateCredential(ctx, tx, store.Credential{
			UserID:     created.ID,
			Kind:       "password",
			Hash:       checked.Hash,
			MustChange: false,
		}); err != nil {
			return err
		}
		if _, err := store.CreateVerificationToken(ctx, tx, store.VerificationToken{
			UserID:    created.ID,
			Kind:      "email_verify",
			TokenHash: tokenHash,
			ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		if err := store.AppendUserLifecycleEvent(ctx, tx, "user.created", nil, &created); err != nil {
			return err
		}
		return appendNotifyEvent(ctx, tx, "user.verification", map[string]any{
			"user_id":    created.ID,
			"email":      request.Email,
			"token":      plaintextToken,
			"expires_at": expiresAt,
		})
	})
	if err != nil {
		if errors.Is(err, passwd.ErrPolicyRejected) {
			writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
			return
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			httpapi.WriteProblem(w, r, http.StatusUnprocessableEntity, "registration failed", "registration could not be completed")
			return
		}
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusCreated, map[string]string{"id": created.ID, "status": created.Status})
}

func (s *Service) verifyEmail(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	var request verifyEmailRequest
	if !decodeJSON(w, r, &request) {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "request body must be valid JSON")
		return
	}
	token := strings.TrimSpace(request.Token)
	if token == "" {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	tokenHash := hashVerificationToken(token)
	err := store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		userID, kind, err := store.ConsumeVerificationToken(ctx, tx, tokenHash)
		if err != nil {
			return err
		}
		if kind != "email_verify" {
			return store.ErrNotFound
		}
		before, err := store.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if err := store.SetEmailVerified(ctx, tx, userID, s.now()); err != nil {
			return err
		}
		if s.registrationMode() == "open" {
			_, err = tx.Exec(ctx, `
                UPDATE users SET status = 'active', updated_at = now()
                WHERE id = $1 AND status = 'pending'`, userID)
			if err != nil {
				return err
			}
		}
		updated, err := store.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		return store.AppendUserLifecycleEvent(ctx, tx, "user.updated", &before, &updated)
	})
	if errors.Is(err, store.ErrNotFound) {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) acceptInvitation(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	var request inviteAcceptRequest
	if !decodeJSON(w, r, &request) {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "request body must be valid JSON")
		return
	}
	request.Token = strings.TrimSpace(request.Token)
	if request.Token == "" {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	now := s.now()
	tokenHash := hashVerificationToken(request.Token)
	token, err := store.PeekVerificationToken(r.Context(), s.q, tokenHash, now)
	if errors.Is(err, store.ErrNotFound) || (err == nil && token.Kind != "invite") {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	var invitation struct {
		Email string `json:"email"`
	}
	if err := json.Unmarshal(token.Payload, &invitation); err != nil || strings.TrimSpace(invitation.Email) == "" {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	userID := token.UserID
	user, err := store.GetUser(r.Context(), s.q, userID)
	if errors.Is(err, pgx.ErrNoRows) || (err == nil && (user.Status != "invited" || user.Email == nil || !strings.EqualFold(strings.TrimSpace(*user.Email), strings.TrimSpace(invitation.Email)))) {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	checked, err := passwd.CheckSet(r.Context(), s.q, userID, request.Password, s.cfg.PwnedPasswordsEnabled, now)
	if errors.Is(err, passwd.ErrPolicyRejected) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		consumedUserID, kind, payload, err := store.ConsumeVerificationTokenWithPayload(ctx, tx, tokenHash)
		if errors.Is(err, store.ErrNotFound) || (err == nil && (kind != "invite" || consumedUserID != userID)) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		var consumedInvitation struct {
			Email string `json:"email"`
		}
		if err := json.Unmarshal(payload, &consumedInvitation); err != nil || !strings.EqualFold(strings.TrimSpace(consumedInvitation.Email), strings.TrimSpace(invitation.Email)) {
			return store.ErrNotFound
		}
		user, err := store.GetUser(ctx, tx, userID)
		if err != nil {
			return err
		}
		if user.Status != "invited" || user.Email == nil || !strings.EqualFold(strings.TrimSpace(*user.Email), strings.TrimSpace(consumedInvitation.Email)) {
			return store.ErrNotFound
		}
		if err := passwd.RecordSet(ctx, tx, checked); err != nil {
			return err
		}
		if _, err := store.CreateCredential(ctx, tx, store.Credential{
			UserID:     userID,
			Kind:       "password",
			Hash:       checked.Hash,
			MustChange: false,
		}); err != nil {
			return err
		}
		updated, err := store.ActivateInvitedUser(ctx, tx, userID, request.DisplayName, s.now())
		if errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := store.AppendUserLifecycleEvent(ctx, tx, "user.updated", &user, &updated); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "invitation.accepted", userID, userID)
	})
	if errors.Is(err, store.ErrNotFound) {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if errors.Is(err, passwd.ErrPolicyRejected) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

// requestPasswordReset deliberately returns the same empty 204 response for
// every request. Identity lookup and token issuance are kept out of the
// response path so callers cannot use the endpoint as an account oracle.
func (s *Service) requestPasswordReset(w http.ResponseWriter, r *http.Request) {
	var request passwordResetRequest
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	err := decoder.Decode(&request)
	login := strings.TrimSpace(request.Login)
	if err != nil || login == "" {
		_ = s.limiter.allowIP(requestIP(r), s.now())
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if !s.limiter.allow(requestIP(r), login, s.now()) {
		w.WriteHeader(http.StatusNoContent)
		return
	}

	var user store.User
	if strings.Contains(login, "@") {
		user, err = store.GetUserByEmail(r.Context(), s.q, login)
	} else {
		user, err = store.GetUserByUsername(r.Context(), s.q, login)
	}
	if err != nil || user.Status != "active" {
		if err != nil && !errors.Is(err, pgx.ErrNoRows) {
			slog.Error("password reset lookup failed", "error", err)
		}
		w.WriteHeader(http.StatusNoContent)
		return
	}

	plaintext, tokenHash, err := newVerificationToken()
	if err != nil {
		slog.Error("password reset token generation failed", "error", err)
		w.WriteHeader(http.StatusNoContent)
		return
	}
	email := ""
	if user.Email != nil {
		email = *user.Email
	}
	expiresAt := s.now().Add(time.Hour)
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		current, err := store.GetUser(ctx, tx, user.ID)
		if errors.Is(err, pgx.ErrNoRows) || (err == nil && current.Status != "active") {
			return nil
		}
		if err != nil {
			return err
		}
		if _, err := store.CreateVerificationToken(ctx, tx, store.VerificationToken{
			UserID: user.ID, Kind: "password_reset", TokenHash: tokenHash, ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		if err := appendNotifyEvent(ctx, tx, "password.reset_requested", map[string]any{
			"user_id": user.ID, "email": email, "token": plaintext,
		}); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "password.reset_requested", user.ID, user.ID)
	})
	if err != nil {
		slog.Error("password reset request failed", "user_id", user.ID, "error", err)
	}
	w.WriteHeader(http.StatusNoContent)
}

// confirmPasswordReset consumes a password-reset token and performs every
// credential/session mutation in one transaction.
func (s *Service) confirmPasswordReset(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	var request passwordResetConfirmRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	token := strings.TrimSpace(request.Token)
	if token == "" {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	now := s.now()
	tokenHash := hashVerificationToken(token)
	verificationToken, err := store.PeekVerificationToken(r.Context(), s.q, tokenHash, now)
	if errors.Is(err, store.ErrNotFound) || (err == nil && verificationToken.Kind != "password_reset") {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	userID := verificationToken.UserID
	checked, err := passwd.CheckSet(r.Context(), s.q, userID, request.NewPassword, s.cfg.PwnedPasswordsEnabled, now)
	if errors.Is(err, passwd.ErrPolicyRejected) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		consumedUserID, kind, err := store.ConsumeVerificationToken(ctx, tx, tokenHash)
		if errors.Is(err, store.ErrNotFound) || (err == nil && (kind != "password_reset" || consumedUserID != userID)) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		if err := passwd.RecordSet(ctx, tx, checked); err != nil {
			return err
		}
		rotatedAt := now
		credential, err := store.GetCredential(ctx, tx, userID, "password")
		if errors.Is(err, pgx.ErrNoRows) {
			_, err = store.CreateCredential(ctx, tx, store.Credential{
				UserID: userID, Kind: "password", Hash: checked.Hash, MustChange: false, RotatedAt: &rotatedAt,
			})
		} else if err == nil {
			credential.Hash = checked.Hash
			credential.RotatedAt = &rotatedAt
			credential.MustChange = false
			_, err = store.UpdateCredential(ctx, tx, credential)
		}
		if err != nil {
			return err
		}
		if err := store.LockSessionPolicyUser(ctx, tx, userID); errors.Is(err, pgx.ErrNoRows) {
			return store.ErrNotFound
		} else if err != nil {
			return err
		}
		if err := store.DeleteAllSessionsForUser(ctx, tx, userID, "user_requested"); err != nil {
			return err
		}
		if err := store.ResetFailedLogins(ctx, tx, userID); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "password.reset_completed", userID, userID)
	})
	if errors.Is(err, store.ErrNotFound) {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if errors.Is(err, passwd.ErrPolicyRejected) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

type clientCredentialsRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type introspectRequest struct {
	Token string `json:"token,omitempty"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type tokenClaims struct {
	Subject      string
	Team         string
	Kind         string
	PermVer      int64
	Expiry       time.Time
	AuthTime     int64
	AMR          []string
	ActorID      string
	Impersonated bool
}

type introspectResponse struct {
	Active  bool              `json:"active"`
	Subject string            `json:"sub,omitempty"`
	Team    string            `json:"team,omitempty"`
	Kind    string            `json:"kind,omitempty"`
	PermVer int64             `json:"perm_ver,omitempty"`
	Exp     int64             `json:"exp,omitempty"`
	Act     map[string]string `json:"act,omitempty"`
	Imp     bool              `json:"imp,omitempty"`
}

type sessionMetadata struct {
	Kind            string   `json:"kind"`
	IP              string   `json:"ip,omitempty"`
	UserAgent       string   `json:"user_agent,omitempty"`
	AuthTime        int64    `json:"auth_time,omitempty"`
	AMR             []string `json:"amr,omitempty"`
	authTimeMissing bool     `json:"-"`
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if !decodeJSON(w, r, &request) {
		if !s.limiter.allowIP(requestIP(r), s.now()) {
			writeRateLimited(w, r)
			return
		}
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, store.User{}, request.Username, "password", "failure")
		writeUnauthorized(w, r)
		return
	}
	user, credential, userErr, credentialErr := s.lookupCredential(r.Context(), request.Username, "password")
	if !s.limiter.allow(requestIP(r), request.Username, s.now()) {
		writeRateLimited(w, r)
		return
	}
	if userErr == nil && user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "failure")
		s.auditAuth(r.Context(), s.q, "auth.login.locked", user, request.Username)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	valid, acquired := s.verifyPassword(r.Context(), credential.Hash, request.Password)
	if !acquired {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeRateLimited(w, r)
		return
	}
	if userErr != nil && !errors.Is(userErr, pgx.ErrNoRows) {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeInternal(w, r)
		return
	}
	if credentialErr != nil && !errors.Is(credentialErr, pgx.ErrNoRows) {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeInternal(w, r)
		return
	}
	if userErr == nil && user.Status == "invited" {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "failure")
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeAuthProblem(w, r, http.StatusForbidden, "account_pending")
		return
	}
	if userErr != nil || credentialErr != nil || !valid {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "failure")
		if userErr == nil && user.ID != "" {
			if err := s.recordLoginFailure(r.Context(), user); err != nil {
				writeInternal(w, r)
				return
			}
		}
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeUnauthorized(w, r)
		return
	}
	if user.Status == "pending" || user.Status == "invited" {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "failure")
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeAuthProblem(w, r, http.StatusForbidden, "account_pending")
		return
	}
	if user.Status != "active" {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "failure")
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeUnauthorized(w, r)
		return
	}
	if credential.MustChange {
		changeToken, err := s.signPasswordChangeToken(user.ID)
		if err != nil {
			writeInternal(w, r)
			return
		}
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "success")
		writePasswordChangeRequired(w, changeToken)
		return
	}
	primaryAuthTime := s.now().Unix()
	policy, err := store.ResolveMFAPolicy(r.Context(), s.q, user.ID, s.now())
	if err != nil {
		writeInternal(w, r)
		return
	}
	required := policy.ID != "" && policy.Required
	_, err = store.GetCredential(r.Context(), s.q, user.ID, "totp")
	hasTOTP := err == nil
	if err != nil && !errors.Is(err, pgx.ErrNoRows) {
		writeInternal(w, r)
		return
	}
	if hasTOTP {
		mfaToken, err := s.signMFAToken(user.ID, primaryAuthTime, []string{"pwd"})
		if err != nil {
			writeInternal(w, r)
			return
		}
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "success")
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_required": true, "mfa_token": mfaToken, "mfa_methods": []string{"otp"},
		})
		return
	}
	if required && policy.DenyUnenrolled {
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "failure")
		writeAuthProblem(w, r, http.StatusForbidden, "mfa_enrollment_denied")
		return
	}
	if required {
		enrollmentToken, err := s.signMFAEnrollmentToken(user.ID, primaryAuthTime, []string{"pwd"})
		if err != nil {
			writeInternal(w, r)
			return
		}
		s.recordLoginActivityFromRequest(r.Context(), s.q, r, user, request.Username, "password", "success")
		writeJSON(w, http.StatusOK, map[string]any{
			"mfa_enrollment_required": true,
			"mfa_token":               enrollmentToken,
			"mfa_methods":             []string{"otp"},
		})
		return
	}
	metadata := sessionMetadataFor(r, "user")
	metadata.AuthTime = primaryAuthTime
	metadata.AMR = []string{"pwd"}
	response, err := s.completeLogin(r.Context(), user, credential, request.Password, "user", metadata)
	if err != nil {
		writeInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) clientCredentials(w http.ResponseWriter, r *http.Request) {
	var request clientCredentialsRequest
	if !decodeJSON(w, r, &request) {
		writeUnauthorized(w, r)
		return
	}
	user, credential, userErr, credentialErr := s.lookupCredential(r.Context(), request.ClientID, "service")
	if userErr == nil && user.LockedUntil != nil && user.LockedUntil.After(s.now()) {
		s.auditAuth(r.Context(), s.q, "auth.login.locked", user, request.ClientID)
		writeAuthProblem(w, r, http.StatusLocked, "account_locked")
		return
	}
	if !s.limiter.allow(requestIP(r), request.ClientID, s.now()) {
		writeRateLimited(w, r)
		return
	}
	valid, acquired := s.verifyPassword(r.Context(), credential.Hash, request.ClientSecret)
	if !acquired {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.ClientID)
		writeRateLimited(w, r)
		return
	}
	if userErr != nil && !errors.Is(userErr, pgx.ErrNoRows) {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.ClientID)
		writeInternal(w, r)
		return
	}
	if credentialErr != nil && !errors.Is(credentialErr, pgx.ErrNoRows) {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.ClientID)
		writeInternal(w, r)
		return
	}
	if userErr != nil || credentialErr != nil || !valid {
		if userErr == nil && user.ID != "" {
			if err := s.recordLoginFailure(r.Context(), user); err != nil {
				writeInternal(w, r)
				return
			}
		}
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.ClientID)
		writeUnauthorized(w, r)
		return
	}
	if user.Status != "active" {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.ClientID)
		writeUnauthorized(w, r)
		return
	}
	response, err := s.completeLogin(r.Context(), user, credential, request.ClientSecret, "service", sessionMetadataFor(r, "service"))
	if err != nil {
		writeInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) lookupCredential(ctx context.Context, username, kind string) (store.User, store.Credential, error, error) {
	user, userErr := store.GetUserByUsername(ctx, s.q, username)
	credential := store.Credential{Hash: s.dummyHash}
	if userErr != nil {
		return user, credential, userErr, nil
	}
	found, credentialErr := store.GetCredential(ctx, s.q, user.ID, kind)
	if credentialErr == nil {
		credential = found
	}
	return user, credential, nil, credentialErr
}

func (s *Service) verifyPassword(ctx context.Context, encoded, password string) (bool, bool) {
	valid, err := passwd.VerifyContext(ctx, encoded, password)
	return valid, err == nil
}

func (s *Service) completeLogin(ctx context.Context, user store.User, credential store.Credential, password, kind string, metadata sessionMetadata) (tokenResponse, error) {
	needsRehash := passwordHashNeedsRehash(credential.Hash)
	var rehashedHash string
	var rotatedAt time.Time
	var historyRetention int
	if needsRehash {
		var err error
		rehashedHash, err = HashPassword(password)
		if err != nil {
			return tokenResponse{}, err
		}
		rotatedAt = s.now()
		historyRetention, err = store.MaxConfiguredPasswordHistoryCount(ctx, s.q, user.ID, rotatedAt)
		if err != nil {
			return tokenResponse{}, err
		}
	}
	var response tokenResponse
	issue := func(txctx context.Context, q store.Q) error {
		if needsRehash {
			if historyRetention > 0 {
				if err := store.LockPasswordHistory(txctx, q, user.ID); err != nil {
					return err
				}
			}
			credential.Hash = rehashedHash
			credential.RotatedAt = &rotatedAt
			if _, err := store.UpdateCredential(txctx, q, credential); err != nil {
				return err
			}
			if historyRetention > 0 {
				if err := store.RecordPasswordHistoryForCount(txctx, q, user.ID, rehashedHash, rotatedAt, historyRetention); err != nil {
					return err
				}
			}
		}
		if err := store.ResetFailedLogins(txctx, q, user.ID); err != nil {
			return err
		}
		var err error
		response, err = s.issuePair(txctx, q, user, kind, "", time.Time{}, metadata)
		if err != nil {
			return err
		}
		if err := s.appendAuthAudit(txctx, q, "auth.login.succeeded", user.ID, user.ID); err != nil {
			return err
		}
		if kind == "user" {
			s.recordLoginActivityFromMetadata(txctx, q, user, "password", "success", metadata)
		}
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

func (s *Service) refresh(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	var request refreshRequest
	if !decodeJSON(w, r, &request) || strings.TrimSpace(request.RefreshToken) == "" {
		writeUnauthorized(w, r)
		return
	}
	response, err := s.rotateRefresh(r.Context(), request.RefreshToken, r)
	if errors.Is(err, errInvalidRefresh) || errors.Is(err, errExpiredRefresh) {
		writeUnauthorized(w, r)
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	writeJSON(w, http.StatusOK, response)
}

func (s *Service) logout(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	var request refreshRequest
	if !decodeJSON(w, r, &request) || strings.TrimSpace(request.RefreshToken) == "" {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	session, err := store.GetSession(r.Context(), s.q, refreshTokenHash(request.RefreshToken))
	if errors.Is(err, pgx.ErrNoRows) {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		if err := store.LockSessionPolicyUser(ctx, tx, session.UserID); err != nil {
			if errors.Is(err, pgx.ErrNoRows) {
				return nil
			}
			return err
		}
		if err := store.RevokeSessionFamily(ctx, tx, session.FamilyID, "logout"); err != nil {
			return err
		}
		return s.appendAuthAudit(ctx, tx, "auth.logout", session.UserID, session.UserID)
	})
	if err != nil {
		writeInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) introspect(w http.ResponseWriter, r *http.Request) {
	if !s.limiter.allowIP(requestIP(r), s.now()) {
		writeRateLimited(w, r)
		return
	}
	if _, _, err := s.authenticateBearer(r, "service"); err != nil {
		writeUnauthorized(w, r)
		return
	}
	var request introspectRequest
	if !decodeJSON(w, r, &request) || strings.TrimSpace(request.Token) == "" {
		writeJSON(w, http.StatusOK, introspectResponse{})
		return
	}
	if claims, err := s.parseAccessToken(request.Token); err == nil {
		user, userErr := store.GetUser(r.Context(), s.q, claims.Subject)
		if userErr == nil && user.Status == "active" && user.PermVer == claims.PermVer {
			response := introspectResponse{
				Active: true, Subject: claims.Subject, Team: claims.Team,
				Kind: claims.Kind, PermVer: claims.PermVer, Exp: claims.Expiry.Unix(),
				Imp: claims.Impersonated,
			}
			if claims.ActorID != "" {
				response.Act = map[string]string{"sub": claims.ActorID}
			}
			writeJSON(w, http.StatusOK, response)
			return
		}
		if userErr != nil && !errors.Is(userErr, pgx.ErrNoRows) {
			writeInternal(w, r)
			return
		}
		writeJSON(w, http.StatusOK, introspectResponse{})
		return
	}

	session, sessionErr := store.GetSession(r.Context(), s.q, refreshTokenHash(request.Token))
	if errors.Is(sessionErr, pgx.ErrNoRows) {
		writeJSON(w, http.StatusOK, introspectResponse{})
		return
	}
	if sessionErr != nil {
		writeInternal(w, r)
		return
	}
	if session.RevokedAt != nil || !session.ExpiresAt.After(s.now()) {
		writeJSON(w, http.StatusOK, introspectResponse{})
		return
	}
	user, userErr := store.GetUser(r.Context(), s.q, session.UserID)
	if errors.Is(userErr, pgx.ErrNoRows) || user.Status != "active" {
		writeJSON(w, http.StatusOK, introspectResponse{})
		return
	}
	if userErr != nil {
		writeInternal(w, r)
		return
	}
	team, err := store.GetUserTeamID(r.Context(), s.q, user.ID)
	if err != nil {
		writeInternal(w, r)
		return
	}
	kind := sessionKind(session)
	writeJSON(w, http.StatusOK, introspectResponse{
		Active: true, Subject: user.ID, Team: team, Kind: kind,
		PermVer: user.PermVer, Exp: session.ExpiresAt.Unix(),
	})
}

func (s *Service) jwks(w http.ResponseWriter, _ *http.Request) {
	set := s.publicSet()
	data, err := json.Marshal(set)
	if err != nil {
		writeJSON(w, http.StatusInternalServerError, map[string]string{"error": "jwks unavailable"})
		return
	}
	w.Header().Set("Content-Type", "application/jwk-set+json")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(data)
}

func (s *Service) issuePair(ctx context.Context, q store.Q, user store.User, kind, familyID string, familyNotAfter time.Time, metadata sessionMetadata) (tokenResponse, error) {
	return s.issuePairWithPolicy(ctx, q, user, kind, familyID, familyNotAfter, "", nil, metadata)
}

func (s *Service) issuePairWithPolicy(ctx context.Context, q store.Q, user store.User, kind, familyID string, familyNotAfter time.Time, replacingSessionID string, policy *store.SessionPolicy, metadata sessionMetadata) (tokenResponse, error) {
	now := s.now()
	if familyID == "" {
		familyID = store.NewID()
		familyNotAfter = now.Add(s.cfg.SessionFamilyTTL)
	}
	if familyNotAfter.IsZero() {
		familyNotAfter = now.Add(s.cfg.SessionFamilyTTL)
	}
	if !now.Before(familyNotAfter) {
		return tokenResponse{}, errExpiredRefresh
	}
	if metadata.AuthTime == 0 {
		if kind == "service" {
			metadata.AuthTime = now.Unix()
		} else if kind != "user" || !metadata.authTimeMissing {
			return tokenResponse{}, errors.New("user authentication time is required")
		}
	}
	if len(metadata.AMR) == 0 {
		metadata.AMR = []string{"pwd"}
	}
	team, err := store.GetUserTeamID(ctx, q, user.ID)
	if err != nil {
		return tokenResponse{}, err
	}
	access, err := s.signAccessToken(user, team, kind, metadata.AuthTime, metadata.AMR)
	if err != nil {
		return tokenResponse{}, err
	}
	refresh, err := newRefreshToken()
	if err != nil {
		return tokenResponse{}, err
	}
	meta, err := json.Marshal(metadata)
	if err != nil {
		return tokenResponse{}, err
	}
	expiresAt := now.Add(s.cfg.RefreshTokenTTL)
	if expiresAt.After(familyNotAfter) {
		expiresAt = familyNotAfter
	}
	if kind != "service" {
		if policy == nil {
			resolved, err := store.ResolveSessionPolicy(ctx, q, user.ID, now)
			if err != nil {
				return tokenResponse{}, err
			}
			policy = &resolved
		}
		if err := store.EnforceConcurrentSessionLimit(ctx, q, user.ID, policy.MaxConcurrentSessions, replacingSessionID, now); err != nil {
			return tokenResponse{}, err
		}
	}
	if _, err := store.CreateSession(ctx, q, store.Session{
		ID:             refreshTokenHash(refresh),
		UserID:         user.ID,
		FamilyID:       familyID,
		ClientMeta:     meta,
		CreatedAt:      now,
		LastActiveAt:   now,
		ExpiresAt:      expiresAt,
		FamilyNotAfter: familyNotAfter,
	}); err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken: access, RefreshToken: refresh,
		TokenType: "Bearer", ExpiresIn: int64(s.cfg.AccessTokenTTL / time.Second),
	}, nil
}
func (s *Service) rotateRefresh(ctx context.Context, refresh string, r *http.Request) (tokenResponse, error) {
	if s.pool == nil {
		return tokenResponse{}, errors.New("refresh rotation requires a pgx pool")
	}
	hash := refreshTokenHash(refresh)
	var response tokenResponse
	var reuseDetected bool
	var reuseUserID string
	var reuseFamilyID string
	var idleExpired bool
	err := store.WithTx(ctx, s.pool, func(txctx context.Context, tx store.Tx) error {
		// All session-governance paths lock the user before the session row.
		sessionUserID, err := store.GetSessionUserID(txctx, tx, hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		if err := store.LockSessionPolicyUser(txctx, tx, sessionUserID); errors.Is(err, pgx.ErrNoRows) {
			return errInvalidRefresh
		} else if err != nil {
			return err
		}
		session, err := store.GetSessionForUpdate(txctx, tx, hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		if session.RevokedAt != nil {
			reason := ""
			if session.RevokeReason != nil {
				reason = *session.RevokeReason
			}
			if reason != "rotated" && reason != "reuse_detected" {
				return errInvalidRefresh
			}
			reuseDetected = true
			reuseUserID = session.UserID
			reuseFamilyID = session.FamilyID
			firstReuse, err := store.RevokeSessionFamilyReuse(txctx, tx, session.FamilyID)
			if err != nil {
				return err
			}
			if !firstReuse {
				return nil
			}
			payload, err := json.Marshal(map[string]string{
				"user_id": session.UserID, "family_id": session.FamilyID,
			})
			if err != nil {
				return err
			}
			if _, err := store.AppendOutboxEvent(txctx, tx, store.OutboxEvent{
				Topic: "notify.session.reuse_detected", Payload: payload,
			}); err != nil {
				return err
			}
			return s.appendAuthAudit(txctx, tx, "auth.refresh.reuse_detected", session.UserID, session.UserID)
		}
		now := s.now()
		if !session.ExpiresAt.After(now) || !session.FamilyNotAfter.After(now) {
			return errExpiredRefresh
		}
		user, err := store.GetUser(txctx, tx, session.UserID)
		if errors.Is(err, pgx.ErrNoRows) || user.Status != "active" {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		kind := sessionKind(session)
		var policy *store.SessionPolicy
		if kind != "service" {
			resolved, err := store.ResolveSessionPolicy(txctx, tx, user.ID, now)
			if err != nil {
				return err
			}
			policy = &resolved
		}
		lastActiveAt := session.LastActiveAt
		if lastActiveAt.IsZero() {
			lastActiveAt = session.CreatedAt
		}
		if policy != nil && sessionIdleExpired(lastActiveAt, policy.IdleTimeoutMinutes, now) {
			if err := store.RevokeSession(txctx, tx, session.ID, "session_idle_expired"); err != nil {
				return err
			}
			idleExpired = true
			return nil
		}
		storedMetadata := sessionMetadataFrom(session)
		metadata := sessionMetadataFor(r, kind)
		metadata.AuthTime = storedMetadata.AuthTime
		metadata.authTimeMissing = metadata.AuthTime == 0
		metadata.AMR = append([]string(nil), storedMetadata.AMR...)
		if len(metadata.AMR) == 0 {
			metadata.AMR = []string{"pwd"}
		}
		response, err = s.issuePairWithPolicy(txctx, tx, user, metadata.Kind, session.FamilyID, session.FamilyNotAfter, session.ID, policy, metadata)
		if err != nil {
			return err
		}
		if err := s.appendAuthAudit(txctx, tx, "auth.refresh.rotated", user.ID, user.ID); err != nil {
			return err
		}
		if err := store.TouchSession(txctx, tx, session.ID, now); err != nil {
			return err
		}
		return store.RevokeSession(txctx, tx, session.ID, "rotated")
	})
	if reuseDetected {
		slog.Warn("refresh token reuse detected", "user_id", reuseUserID, "family_id", reuseFamilyID)
		if err != nil {
			return tokenResponse{}, err
		}
		return tokenResponse{}, errInvalidRefresh
	}
	if idleExpired {
		if err != nil {
			return tokenResponse{}, err
		}
		return tokenResponse{}, errExpiredRefresh
	}
	if errors.Is(err, errInvalidRefresh) || errors.Is(err, errExpiredRefresh) {
		return tokenResponse{}, err
	}
	return response, err
}

func (s *Service) signAccessToken(user store.User, team, kind string, authTime int64, amr []string) (string, error) {
	now := s.now()
	return s.signAccessTokenAt(user, team, kind, authTime, amr, now, now.Add(s.cfg.AccessTokenTTL), nil)
}

func (s *Service) signAccessTokenAt(user store.User, team, kind string, authTime int64, amr []string, issuedAt, expiresAt time.Time, additionalClaims map[string]interface{}) (string, error) {
	token := jwt.New()
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	claims := map[string]interface{}{
		"iss":       issuer,
		"aud":       audience,
		"sub":       user.ID,
		"kind":      kind,
		"perm_ver":  user.PermVer,
		"iat":       issuedAt,
		"exp":       expiresAt,
		"jti":       store.NewID(),
		"auth_time": authTime,
		"amr":       amr,
	}
	if team != "" {
		claims["team"] = team
	}
	for name, value := range additionalClaims {
		claims[name] = value
	}
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return "", fmt.Errorf("set access claim %q: %w", name, err)
		}
	}
	key, ok := s.activeSigningKey()
	if !ok {
		return "", errors.New("active signing key unavailable")
	}
	signed, err := jwt.Sign(token, jwt.WithKey(jwa.EdDSA, key.private))
	if err != nil {
		return "", fmt.Errorf("sign access token: %w", err)
	}
	return string(signed), nil
}
func (s *Service) parseAccessToken(raw string) (tokenClaims, error) {
	set := s.publicSet()
	token, err := jwt.Parse([]byte(raw), jwt.WithKeySet(set), jwt.WithValidate(true))
	if err != nil {
		return tokenClaims{}, err
	}
	if token.Issuer() != issuer || token.Subject() == "" || token.Expiration().IsZero() || !token.Expiration().After(s.now()) {
		return tokenClaims{}, errors.New("invalid access token claims")
	}
	audience := strings.TrimSpace(s.cfg.TokenAudience)
	if audience == "" {
		audience = issuer
	}
	audiences := token.Audience()
	if len(audiences) != 1 || audiences[0] != audience {
		return tokenClaims{}, errors.New("invalid access token audience")
	}
	team := ""
	if value, present := token.Get("team"); present {
		var ok bool
		team, ok = value.(string)
		if !ok {
			return tokenClaims{}, errors.New("invalid team claim")
		}
	}
	kind, ok := stringClaim(token, "kind")
	if !ok || (kind != "user" && kind != "service") {
		return tokenClaims{}, errors.New("invalid kind claim")
	}
	permVer, ok := int64Claim(token, "perm_ver")
	if !ok || permVer < 0 {
		return tokenClaims{}, errors.New("invalid perm_ver claim")
	}
	authTime := int64(0)
	if _, present := token.Get("auth_time"); present {
		authTime, ok = int64Claim(token, "auth_time")
		if !ok || authTime < 0 {
			return tokenClaims{}, errors.New("invalid auth_time claim")
		}
	}
	amr := []string(nil)
	if _, present := token.Get("amr"); present {
		amr, ok = stringSliceClaim(token, "amr")
		if !ok {
			return tokenClaims{}, errors.New("invalid amr claim")
		}
	}
	actorID := ""
	if value, present := token.Get("act"); present {
		switch actor := value.(type) {
		case map[string]interface{}:
			actorID, ok = actor["sub"].(string)
		case map[string]string:
			actorID, ok = actor["sub"]
		default:
			return tokenClaims{}, errors.New("invalid act claim")
		}
		if !ok || actorID == "" {
			return tokenClaims{}, errors.New("invalid act claim")
		}
	}
	impersonated := false
	if value, present := token.Get("imp"); present {
		impersonated, ok = value.(bool)
		if !ok {
			return tokenClaims{}, errors.New("invalid imp claim")
		}
	}
	if impersonated && actorID == "" {
		return tokenClaims{}, errors.New("invalid impersonation claims")
	}
	return tokenClaims{
		Subject: token.Subject(), Team: team, Kind: kind, PermVer: permVer,
		Expiry: token.Expiration(), AuthTime: authTime, AMR: amr,
		ActorID: actorID, Impersonated: impersonated,
	}, nil
}

func (s *Service) publicSet() jwk.Set {
	set := jwk.NewSet()
	now := s.now()
	s.keyMu.RLock()
	defer s.keyMu.RUnlock()
	for _, key := range s.keys {
		if !key.retireAt.IsZero() && !now.Before(key.retireAt) {
			continue
		}
		_ = set.AddKey(key.public)
	}
	return set
}

func stringClaim(token jwt.Token, name string) (string, bool) {
	value, ok := token.Get(name)
	if !ok {
		return "", false
	}
	text, ok := value.(string)
	return text, ok
}

func stringSliceClaim(token jwt.Token, name string) ([]string, bool) {
	value, ok := token.Get(name)
	if !ok {
		return nil, false
	}
	switch values := value.(type) {
	case []string:
		return append([]string(nil), values...), true
	case []interface{}:
		result := make([]string, len(values))
		for i, value := range values {
			text, ok := value.(string)
			if !ok {
				return nil, false
			}
			result[i] = text
		}
		return result, true
	default:
		return nil, false
	}
}

func int64Claim(token jwt.Token, name string) (int64, bool) {
	value, ok := token.Get(name)
	if !ok {
		return 0, false
	}
	switch number := value.(type) {
	case int:
		return int64(number), true
	case int64:
		return number, true
	case int32:
		return int64(number), true
	case uint:
		return int64(number), uint64(number) <= uint64(^uint64(0)>>1)
	case uint64:
		return int64(number), number <= uint64(^uint64(0)>>1)
	case float64:
		return int64(number), number >= 0 && number == float64(int64(number))
	case json.Number:
		parsed, err := number.Int64()
		return parsed, err == nil
	default:
		return 0, false
	}
}

func sessionMetadataFor(r *http.Request, kind string) sessionMetadata {
	if r == nil {
		return sessionMetadata{Kind: kind}
	}
	return sessionMetadata{Kind: kind, IP: requestIP(r), UserAgent: r.UserAgent()}
}

func sessionMetadataFrom(session store.Session) sessionMetadata {
	var metadata sessionMetadata
	if len(session.ClientMeta) > 0 {
		if err := json.Unmarshal(session.ClientMeta, &metadata); err != nil {
			return sessionMetadata{}
		}
	}
	return metadata
}

func sessionKind(session store.Session) string {
	kind := sessionMetadataFrom(session).Kind
	if kind == "service" {
		return kind
	}
	return "user"
}

func newRefreshToken() (string, error) {
	data := make([]byte, refreshTokenSize)
	if _, err := rand.Read(data); err != nil {
		return "", fmt.Errorf("generate refresh token: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(data), nil
}

func refreshTokenHash(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func (s *Service) registrationMode() string {
	switch mode := strings.ToLower(strings.TrimSpace(s.cfg.RegistrationMode)); mode {
	case "approval", "open":
		return mode
	default:
		return "closed"
	}
}

func newVerificationToken() (string, string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", "", fmt.Errorf("generate verification token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(data)
	return plaintext, hashVerificationToken(plaintext), nil
}

func hashVerificationToken(token string) string {
	sum := sha256.Sum256([]byte(token))
	return hex.EncodeToString(sum[:])
}

func appendNotifyEvent(ctx context.Context, q store.Q, topic string, payload any) error {
	data, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	_, err = store.AppendOutboxEvent(ctx, q, store.OutboxEvent{Topic: "notify." + topic, Payload: data})
	return err
}

func writeAuthProblem(w http.ResponseWriter, r *http.Request, status int, code string) {
	httpapi.WriteProblem(w, r, status, code, code)
}

func bearerToken(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

func requestIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(strings.TrimSpace(r.RemoteAddr))
	if err == nil {
		return host
	}
	return strings.TrimSpace(r.RemoteAddr)
}

func decodeJSON(w http.ResponseWriter, r *http.Request, value any) bool {
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20))
	if err := decoder.Decode(value); err != nil {
		return false
	}
	return true
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeUnauthorized(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "authentication failed")
}

func writePasswordChangeRequired(w http.ResponseWriter, changeToken string) {
	w.Header().Set("Content-Type", "application/problem+json")
	w.WriteHeader(http.StatusForbidden)
	_ = json.NewEncoder(w).Encode(struct {
		Type        string `json:"type"`
		Title       string `json:"title"`
		Status      int    `json:"status"`
		Detail      string `json:"detail"`
		ChangeToken string `json:"change_token"`
	}{
		Type: "about:blank", Title: "password_change_required", Status: http.StatusForbidden,
		Detail: "password_change_required", ChangeToken: changeToken,
	})
}

func writeInternal(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "authentication service unavailable")
}

func (s *Service) appendAuthAudit(ctx context.Context, q store.Q, action, actorID, target string) error {
	if s.audit == nil {
		return nil
	}
	var actor *string
	if actorID != "" {
		value := actorID
		actor = &value
	}
	_, err := s.audit.Append(ctx, q, auditlog.Entry{ActorID: actor, Action: action, Target: target})
	return err
}

func (s *Service) auditAuth(ctx context.Context, q store.Q, action string, user store.User, fallback string) {
	actorID := ""
	target := fallback
	if user.ID != "" {
		actorID = user.ID
		target = user.ID
	}
	if err := s.appendAuthAudit(ctx, q, action, actorID, target); err != nil {
		slog.Error("append authentication audit event failed", "action", action, "target", target, "error", err)
	}
}

func (s *Service) recordLoginActivityFromRequest(ctx context.Context, q store.Q, r *http.Request, user store.User, attemptedUsername, method, result string) {
	ip, userAgent := "", ""
	if r != nil {
		ip = requestIP(r)
		userAgent = r.UserAgent()
	}
	s.recordLoginActivity(ctx, q, user, attemptedUsername, ip, userAgent, method, result)
}

func (s *Service) recordLoginActivityFromMetadata(ctx context.Context, q store.Q, user store.User, method, result string, metadata sessionMetadata) {
	s.recordLoginActivity(ctx, q, user, "", metadata.IP, metadata.UserAgent, method, result)
}

func (s *Service) recordLoginActivity(ctx context.Context, q store.Q, user store.User, attemptedUsername, ip, userAgent, method, result string) {
	entry := store.LoginActivity{
		At: s.now(), IP: ip, UserAgent: userAgent, Method: method, Result: result,
	}
	if user.ID != "" {
		userID := user.ID
		entry.UserID = &userID
	} else {
		entry.AttemptedUsername = strings.TrimSpace(attemptedUsername)
	}
	if _, inTx := q.(store.Tx); inTx {
		const savepoint = "teamusers_login_activity_write"
		if _, err := q.Exec(ctx, "SAVEPOINT "+savepoint); err != nil {
			slog.Error("create login activity savepoint failed", "method", method, "error", err)
			return
		}
		if err := store.CreateLoginActivity(ctx, q, entry); err != nil {
			if _, rollbackErr := q.Exec(ctx, "ROLLBACK TO SAVEPOINT "+savepoint); rollbackErr != nil {
				slog.Error("rollback login activity savepoint failed", "method", method, "error", rollbackErr)
			}
			if _, releaseErr := q.Exec(ctx, "RELEASE SAVEPOINT "+savepoint); releaseErr != nil {
				slog.Error("release login activity savepoint failed", "method", method, "error", releaseErr)
			}
			slog.Error("record login activity failed", "method", method, "result", result, "error", err)
			return
		}
		if _, err := q.Exec(ctx, "RELEASE SAVEPOINT "+savepoint); err != nil {
			slog.Error("release login activity savepoint failed", "method", method, "error", err)
		}
		return
	}
	if err := store.CreateLoginActivity(ctx, q, entry); err != nil {
		slog.Error("record login activity failed", "method", method, "result", result, "error", err)
	}
}

func sessionIdleExpired(lastActiveAt time.Time, idleTimeoutMinutes *int, now time.Time) bool {
	if idleTimeoutMinutes == nil || *idleTimeoutMinutes <= 0 || lastActiveAt.IsZero() {
		return false
	}
	const maxTimeoutMinutes = int64((1<<63 - 1) / int64(time.Minute))
	if int64(*idleTimeoutMinutes) > maxTimeoutMinutes {
		return false
	}
	return now.Sub(lastActiveAt) > time.Duration(*idleTimeoutMinutes)*time.Minute
}

func (s *Service) reapExpiredSessions(ctx context.Context) {
	ticker := time.NewTicker(time.Hour)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			count, err := store.DeleteExpiredSessions(ctx, s.pool, s.now())
			if err != nil {
				slog.Error("reap expired sessions failed", "error", err)
				continue
			}
			slog.Debug("reaped expired sessions", "count", count)
		case <-ctx.Done():
			return
		}
	}
}

func writeRateLimited(w http.ResponseWriter, r *http.Request) {
	httpapi.WriteProblem(w, r, http.StatusTooManyRequests, "Too Many Requests", "authentication temporarily busy")
}
