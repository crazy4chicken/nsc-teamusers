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
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/lestrrat-go/jwx/v2/jwa"
	"github.com/lestrrat-go/jwx/v2/jwk"
	"github.com/lestrrat-go/jwx/v2/jwt"

	auditlog "nsc-teamusers/internal/audit"
	"nsc-teamusers/internal/config"
	"nsc-teamusers/internal/httpapi"
	"nsc-teamusers/internal/store"
)

const (
	issuer           = "nsc-teamusers"
	AccessTokenTTL   = 10 * time.Minute
	RefreshTokenTTL  = 30 * 24 * time.Hour
	FamilyMaxTTL     = 90 * 24 * time.Hour
	refreshTokenSize = 32
	argonSlots       = 4
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
	cfg        config.Config
	q          store.Q
	pool       *pgxpool.Pool
	keys       map[string]signingKey
	activeKid  string
	limiter    *loginLimiter
	dummyHash  string
	argonSlots chan struct{}
	audit      *auditlog.Writer
	now        func() time.Time
}

func New(deps Deps) (*Service, error) {
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
	keys, activeKid, err := loadSigningKeys(deps.Config.KeyDir)
	if err != nil {
		return nil, err
	}
	if deps.Audit == nil {
		deps.Audit = auditlog.NewWriter()
	}
	service := &Service{
		cfg:        deps.Config,
		q:          q,
		pool:       pool,
		keys:       keys,
		activeKid:  activeKid,
		limiter:    newLoginLimiter(),
		dummyHash:  newDummyPasswordHash(),
		argonSlots: make(chan struct{}, argonSlots),
		audit:      deps.Audit,
		now:        time.Now,
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

// Routes returns the public authentication and JWKS routes.
func (s *Service) Routes() chi.Router {
	router := chi.NewRouter()
	router.Post("/auth/login", s.login)
	router.Post("/auth/client-credentials", s.clientCredentials)
	router.Post("/auth/refresh", s.refresh)
	router.Post("/auth/logout", s.logout)
	router.Post("/auth/introspect", s.introspect)
	router.Get("/.well-known/jwks.json", s.jwks)
	return router
}

// Middleware verifies an access JWT, checks that its subject remains active,
// and injects the HTTP API subject used by the admin plane.
func (s *Service) Middleware() func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			claims, _, err := s.authenticateBearer(r, "")
			if err != nil {
				writeUnauthorized(w, r)
				return
			}
			subject := httpapi.Subject{
				UserID: claims.Subject, TeamID: claims.Team, Kind: claims.Kind, PermVer: claims.PermVer,
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

type clientCredentialsRequest struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type refreshRequest struct {
	RefreshToken string `json:"refresh_token"`
}

type introspectRequest struct {
	Token string `json:"token"`
}

type tokenResponse struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type tokenClaims struct {
	Subject string
	Team    string
	Kind    string
	PermVer int64
	Expiry  time.Time
}

type introspectResponse struct {
	Active  bool   `json:"active"`
	Subject string `json:"sub,omitempty"`
	Team    string `json:"team,omitempty"`
	Kind    string `json:"kind,omitempty"`
	PermVer int64  `json:"perm_ver,omitempty"`
	Exp     int64  `json:"exp,omitempty"`
}

type sessionMetadata struct {
	Kind      string `json:"kind"`
	IP        string `json:"ip,omitempty"`
	UserAgent string `json:"user_agent,omitempty"`
}

func (s *Service) login(w http.ResponseWriter, r *http.Request) {
	var request loginRequest
	if !decodeJSON(w, r, &request) {
		writeUnauthorized(w, r)
		return
	}
	if !s.limiter.allow(requestIP(r), request.Username, s.now()) {
		writeRateLimited(w, r)
		return
	}
	user, credential, userErr, credentialErr := s.lookupCredential(r.Context(), request.Username, "password")
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
	if userErr != nil || credentialErr != nil || !valid || user.Status != "active" {
		s.auditAuth(r.Context(), s.q, "auth.login.failed", user, request.Username)
		writeUnauthorized(w, r)
		return
	}
	response, err := s.completeLogin(r.Context(), user, credential, request.Password, "user", sessionMetadataFor(r, "user"))
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
	if !s.limiter.allow(requestIP(r), request.ClientID, s.now()) {
		writeRateLimited(w, r)
		return
	}
	user, credential, userErr, credentialErr := s.lookupCredential(r.Context(), request.ClientID, "service")
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
	if userErr != nil || credentialErr != nil || !valid || user.Status != "active" {
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
	timer := time.NewTimer(2 * time.Second)
	defer timer.Stop()
	select {
	case s.argonSlots <- struct{}{}:
		defer func() { <-s.argonSlots }()
		return VerifyPassword(encoded, password), true
	case <-timer.C:
		return false, false
	case <-ctx.Done():
		return false, false
	}
}

func (s *Service) completeLogin(ctx context.Context, user store.User, credential store.Credential, password, kind string, metadata sessionMetadata) (tokenResponse, error) {
	needsRehash := passwordHashNeedsRehash(credential.Hash)
	var response tokenResponse
	issue := func(txctx context.Context, q store.Q) error {
		if needsRehash {
			hash, err := HashPassword(password)
			if err != nil {
				return err
			}
			rotatedAt := s.now()
			credential.Hash = hash
			credential.RotatedAt = &rotatedAt
			if _, err := store.UpdateCredential(txctx, q, credential); err != nil {
				return err
			}
		}
		var err error
		response, err = s.issuePair(txctx, q, user, kind, "", time.Time{}, metadata)
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
	if err := store.RevokeSessionFamily(r.Context(), s.q, session.FamilyID, "logout"); err != nil {
		writeInternal(w, r)
		return
	}
	if err := s.appendAuthAudit(r.Context(), s.q, "auth.logout", session.UserID, session.UserID); err != nil {
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
			writeJSON(w, http.StatusOK, introspectResponse{
				Active: true, Subject: claims.Subject, Team: claims.Team,
				Kind: claims.Kind, PermVer: claims.PermVer, Exp: claims.Expiry.Unix(),
			})
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
	now := s.now()
	if familyID == "" {
		familyID = store.NewID()
		familyNotAfter = now.Add(FamilyMaxTTL)
	}
	if familyNotAfter.IsZero() {
		familyNotAfter = now.Add(FamilyMaxTTL)
	}
	if !now.Before(familyNotAfter) {
		return tokenResponse{}, errExpiredRefresh
	}
	team, err := store.GetUserTeamID(ctx, q, user.ID)
	if err != nil {
		return tokenResponse{}, err
	}
	access, err := s.signAccessToken(user, team, kind)
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
	expiresAt := now.Add(RefreshTokenTTL)
	if expiresAt.After(familyNotAfter) {
		expiresAt = familyNotAfter
	}
	if _, err := store.CreateSession(ctx, q, store.Session{
		ID:             refreshTokenHash(refresh),
		UserID:         user.ID,
		FamilyID:       familyID,
		ClientMeta:     meta,
		ExpiresAt:      expiresAt,
		FamilyNotAfter: familyNotAfter,
	}); err != nil {
		return tokenResponse{}, err
	}
	return tokenResponse{
		AccessToken: access, RefreshToken: refresh,
		TokenType: "Bearer", ExpiresIn: int64(AccessTokenTTL / time.Second),
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
	err := store.WithTx(ctx, s.pool, func(txctx context.Context, tx store.Tx) error {
		session, err := store.GetSessionForUpdate(txctx, tx, hash)
		if errors.Is(err, pgx.ErrNoRows) {
			return errInvalidRefresh
		}
		if err != nil {
			return err
		}
		if session.RevokedAt != nil {
			reuseDetected = true
			reuseUserID = session.UserID
			reuseFamilyID = session.FamilyID
			if err := store.RevokeSessionFamilyReuse(txctx, tx, session.FamilyID); err != nil {
				return err
			}
			payload, err := json.Marshal(map[string]string{
				"user_id": session.UserID, "family_id": session.FamilyID,
			})
			if err != nil {
				return err
			}
			if _, err := store.AppendOutboxEvent(txctx, tx, store.OutboxEvent{
				Topic: "webhook.session.reuse_detected", Payload: payload,
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
		metadata := sessionMetadataFor(r, sessionKind(session))
		response, err = s.issuePair(txctx, tx, user, metadata.Kind, session.FamilyID, session.FamilyNotAfter, metadata)
		if err != nil {
			return err
		}
		if err := s.appendAuthAudit(txctx, tx, "auth.refresh.rotated", user.ID, user.ID); err != nil {
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
	if errors.Is(err, errInvalidRefresh) || errors.Is(err, errExpiredRefresh) {
		return tokenResponse{}, err
	}
	return response, err
}

func (s *Service) signAccessToken(user store.User, team, kind string) (string, error) {
	now := s.now()
	token := jwt.New()
	claims := map[string]interface{}{
		"iss":      issuer,
		"sub":      user.ID,
		"kind":     kind,
		"perm_ver": user.PermVer,
		"iat":      now,
		"exp":      now.Add(AccessTokenTTL),
		"jti":      store.NewID(),
	}
	if team != "" {
		claims["team"] = team
	}
	for name, value := range claims {
		if err := token.Set(name, value); err != nil {
			return "", fmt.Errorf("set access claim %q: %w", name, err)
		}
	}
	key, ok := s.keys[s.activeKid]
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
	return tokenClaims{Subject: token.Subject(), Team: team, Kind: kind, PermVer: permVer, Expiry: token.Expiration()}, nil
}

func (s *Service) publicSet() jwk.Set {
	set := jwk.NewSet()
	for _, key := range s.keys {
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
		_ = json.Unmarshal(session.ClientMeta, &metadata)
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
