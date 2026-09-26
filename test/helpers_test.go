package test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"teamusers/internal/audit"
	"teamusers/internal/authn"
	"teamusers/internal/authz"
	"teamusers/internal/config"
	"teamusers/internal/httpapi"
	"teamusers/internal/store"
	"teamusers/migrations"
)

const testPostgresEnv = "TEAMUSERS_TEST_PG"

type integrationDatabase struct {
	pool             *pgxpool.Pool
	connectionString string
}

type integrationStack struct {
	database *integrationDatabase
	server   *httpapi.Server
	client   *http.Client
	baseURL  string
}

type tokenPair struct {
	AccessToken  string `json:"access_token"`
	RefreshToken string `json:"refresh_token"`
	TokenType    string `json:"token_type"`
	ExpiresIn    int64  `json:"expires_in"`
}

type userResponse struct {
	ID       string `json:"id"`
	Username string `json:"username"`
}

type teamResponse struct {
	ID string `json:"id"`
}

type groupResponse struct {
	ID string `json:"id"`
}

type roleResponse struct {
	ID string `json:"id"`
}

type credentialResponse struct {
	ClientID     string `json:"client_id"`
	ClientSecret string `json:"client_secret"`
}

type introspectionResponse struct {
	Active  bool   `json:"active"`
	Subject string `json:"sub"`
	Kind    string `json:"kind"`
}

type jwksResponse struct {
	Keys []json.RawMessage `json:"keys"`
}

type permissionsResponse struct {
	Grants []struct {
		Key string `json:"key"`
	} `json:"grants"`
}

type checkResponse struct {
	Allow bool `json:"allow"`
}

type auditResponse struct {
	Items []struct {
		Action string `json:"action"`
	} `json:"items"`
}

func newIntegrationStack(t *testing.T) *integrationStack {
	return newIntegrationStackWithMode(t, "closed")
}

func newIntegrationStackWithMode(t *testing.T, registrationMode string) *integrationStack {
	return newIntegrationStackWithModeAndConfig(t, registrationMode, nil)
}

func newIntegrationStackWithModeAndConfig(t *testing.T, registrationMode string, configure func(*config.Config)) *integrationStack {
	t.Helper()
	database := newIntegrationDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())

	cfg := config.Config{
		ConnectionString: database.connectionString,
		ListenAddress:    "127.0.0.1",
		ListenPort:       0,
		LogLevel:         "error",
		KeyDir:           t.TempDir(),
		RegistrationMode: registrationMode,
	}
	if configure != nil {
		configure(&cfg)
	}
	server := httpapi.NewServer(cfg, database.pool)
	if err := server.Listen(); err != nil {
		cancel()
		t.Fatalf("listen integration server: %v", err)
	}

	auditWriter := audit.NewWriter()
	authService, err := authn.New(authn.Dependencies{
		Config:  cfg,
		Q:       database.pool,
		Pool:    database.pool,
		Audit:   auditWriter,
		Context: ctx,
	})
	if err != nil {
		cancel()
		_ = server.Shutdown(context.Background())
		t.Fatalf("initialize integration authentication: %v", err)
	}
	authRoutes := authService.Routes()
	meRoutes := authService.MeRoutes()
	authzRoutes := authz.NewRouter(database.pool, authService.Middleware())
	adminRoutes := httpapi.NewAdminRouter(database.pool, auditWriter, authService.Middleware(), cfg)
	server.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/authz/") || r.URL.Path == "/authz" {
			authzRoutes.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/.well-known/jwks.json" {
			authRoutes.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/me/") || r.URL.Path == "/me" {
			meRoutes.ServeHTTP(w, r)
			return
		}
		adminRoutes.ServeHTTP(w, r)
	}))

	serverErrors := make(chan error, 1)
	go func() {
		serverErrors <- server.ListenAndServe()
	}()
	t.Logf("integration HTTP server listening at %s", server.Addr())

	stack := &integrationStack{
		database: database,
		server:   server,
		client:   &http.Client{Timeout: 30 * time.Second},
		baseURL:  "http://" + server.Addr(),
	}
	t.Cleanup(func() {
		cancel()
		shutdownContext, shutdownCancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer shutdownCancel()
		if err := server.Shutdown(shutdownContext); err != nil {
			t.Logf("shutdown integration HTTP server: %v", err)
		}
		select {
		case err := <-serverErrors:
			if err != nil && !errors.Is(err, http.ErrServerClosed) {
				t.Logf("integration HTTP server: %v", err)
			}
		case <-shutdownContext.Done():
			t.Log("timed out waiting for integration HTTP server")
		}
	})
	return stack
}

// completeForcedPasswordChange performs the forced first-login flow: login with
// the provisioned password (expects 403 + change_token), then POST /me/password
// with the change token to set newPassword.
func completeForcedPasswordChange(t *testing.T, stack *integrationStack, username, provisionedPassword, newPassword string) {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": username,
		"password": provisionedPassword,
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "password_change_required") {
		t.Fatalf("provisioned login = %d %s, want password_change_required 403", status, body)
	}
	var challenge struct {
		ChangeToken string `json:"change_token"`
	}
	decodeResponse(t, body, &challenge)
	if challenge.ChangeToken == "" {
		t.Fatal("provisioned login response has no change_token")
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": provisionedPassword,
		"new_password":     newPassword,
	}, challenge.ChangeToken)
	if status != http.StatusOK {
		t.Fatalf("forced password change = %d %s, want 200", status, body)
	}
}

func newIntegrationDatabase(t *testing.T) *integrationDatabase {
	t.Helper()
	adminDSN := strings.TrimSpace(os.Getenv(testPostgresEnv))
	if adminDSN == "" {
		t.Skipf("%s is unset", testPostgresEnv)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	adminPool, err := store.NewPool(ctx, adminDSN)
	if err != nil {
		t.Fatalf("connect PostgreSQL admin pool: %v", err)
	}
	dbName := "teamusers_test_" + strings.ToLower(store.NewID())
	created := false
	var targetPool *pgxpool.Pool
	t.Cleanup(func() {
		if targetPool != nil {
			targetPool.Close()
		}
		dropContext, dropCancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer dropCancel()
		if created {
			if _, err := adminPool.Exec(dropContext, "DROP DATABASE IF EXISTS "+quoteIdentifier(dbName)); err != nil {
				t.Logf("drop integration database %s: %v", dbName, err)
			}
		}
		adminPool.Close()
	})
	if err := adminPool.Ping(ctx); err != nil {
		t.Fatalf("ping PostgreSQL admin pool: %v", err)
	}
	if _, err := adminPool.Exec(ctx, "CREATE DATABASE "+quoteIdentifier(dbName)); err != nil {
		t.Fatalf("create integration database %s: %v", dbName, err)
	}
	created = true

	poolConfig, err := pgxpool.ParseConfig(adminDSN)
	if err != nil {
		t.Fatalf("parse PostgreSQL pool config: %v", err)
	}
	poolConfig.ConnConfig.Database = dbName
	targetDSN := stdlib.RegisterConnConfig(poolConfig.ConnConfig)

	migrationDB, err := goose.OpenDBWithDriver("pgx", targetDSN)
	if err != nil {
		t.Fatalf("open migration database: %v", err)
	}
	migrationDB.SetMaxOpenConns(1)
	migrationDB.SetMaxIdleConns(1)
	if err := migrationDB.PingContext(ctx); err != nil {
		migrationDB.Close()
		t.Fatalf("ping migration database: %v", err)
	}
	if err := goose.SetDialect("postgres"); err != nil {
		migrationDB.Close()
		t.Fatalf("set goose dialect: %v", err)
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetVerbose(false)
	if err := goose.UpContext(ctx, migrationDB, "."); err != nil {
		migrationDB.Close()
		t.Fatalf("run embedded migrations: %v", err)
	}
	if err := migrationDB.Close(); err != nil {
		t.Fatalf("close migration database: %v", err)
	}

	targetPool, err = pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		t.Fatalf("open integration database pool: %v", err)
	}
	if err := targetPool.Ping(ctx); err != nil {
		targetPool.Close()
		targetPool = nil
		t.Fatalf("ping integration database: %v", err)
	}
	return &integrationDatabase{pool: targetPool, connectionString: targetDSN}
}

func seedPasswordUser(t *testing.T, ctx context.Context, q store.Q, username, password string) store.User {
	t.Helper()
	hash, err := authn.HashPassword(password)
	if err != nil {
		t.Fatalf("hash bootstrap password: %v", err)
	}
	user, err := store.CreateUser(ctx, q, store.User{
		Username:    username,
		DisplayName: username,
		Status:      "active",
	})
	if err != nil {
		t.Fatalf("create bootstrap user %q: %v", username, err)
	}
	if _, err := store.CreateCredential(ctx, q, store.Credential{
		UserID: user.ID,
		Kind:   "password",
		Hash:   hash,
	}); err != nil {
		t.Fatalf("create bootstrap credential %q: %v", username, err)
	}
	return user
}

var testBootstrapAdminPermissionKeys = []string{
	"iam:users:any",
	"iam:teams:any",
	"iam:groups:any",
	"iam:roles:any",
	"iam:permissions:any",
	"iam:bindings:any",
	"iam:audit:any",
	"iam:sessions:any",
}

func bootstrapTestAdmin(t *testing.T, ctx context.Context, q store.Q, userID string) {
	t.Helper()
	err := store.WithAdminTx(ctx, q, func(ctx context.Context, tx store.Tx) error {
		permissionAdded := false
		for _, key := range testBootstrapAdminPermissionKeys {
			tag, err := tx.Exec(ctx, `
                INSERT INTO permissions (key, description, registered_by)
                VALUES ($1, $2, $3)
                ON CONFLICT (key) DO NOTHING`, key, "integration admin permission", "integration")
			if err != nil {
				return err
			}
			permissionAdded = permissionAdded || tag.RowsAffected() > 0
		}
		if permissionAdded {
			if _, err := store.BumpPermissionRegistryPermVer(ctx, tx); err != nil {
				return err
			}
		}

		var roleID string
		err := tx.QueryRow(ctx, `
            SELECT id FROM roles
            WHERE team_id IS NULL AND name = $1
            ORDER BY id LIMIT 1`, "iam-admin").Scan(&roleID)
		if errors.Is(err, pgx.ErrNoRows) {
			role, err := store.CreateRole(ctx, tx, store.Role{Name: "iam-admin"})
			if err != nil {
				return err
			}
			roleID = role.ID
		} else if err != nil {
			return err
		}

		permissionChanged := false
		for _, key := range testBootstrapAdminPermissionKeys {
			tag, err := tx.Exec(ctx, `
                INSERT INTO role_permissions (role_id, permission_key)
                VALUES ($1, $2)
                ON CONFLICT (role_id, permission_key) DO NOTHING`, roleID, key)
			if err != nil {
				return err
			}
			permissionChanged = permissionChanged || tag.RowsAffected() > 0
		}

		var bound bool
		if err := tx.QueryRow(ctx, `
            SELECT EXISTS(
                SELECT 1 FROM role_bindings
                WHERE role_id = $1 AND subject_kind = 'user' AND subject_id = $2
            )`, roleID, userID).Scan(&bound); err != nil {
			return err
		}
		if !bound {
			if _, err := store.CreateRoleBinding(ctx, tx, store.RoleBinding{
				RoleID: roleID, SubjectKind: "user", SubjectID: userID,
			}); err != nil {
				return err
			}
			permissionChanged = true
		}
		if permissionChanged {
			_, err := store.BumpUserPermVer(ctx, tx, userID)
			return err
		}
		return nil
	})
	if err != nil {
		t.Fatalf("bootstrap integration admin %q: %v", userID, err)
	}
}

func loginUser(t *testing.T, stack *integrationStack, username, password string) string {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": username,
		"password": password,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login %q status = %d, want %d: %s", username, status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	return pair.AccessToken
}

func (s *integrationStack) jsonRequest(t *testing.T, method, path string, requestBody any, bearer string) (int, []byte) {
	t.Helper()
	return s.jsonRequestHeaders(t, method, path, requestBody, bearer, nil)
}

func (s *integrationStack) jsonRequestHeaders(t *testing.T, method, path string, requestBody any, bearer string, headers map[string]string) (int, []byte) {
	t.Helper()
	var body io.Reader
	if requestBody != nil {
		encoded, err := json.Marshal(requestBody)
		if err != nil {
			t.Fatalf("encode %s %s request: %v", method, path, err)
		}
		body = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, s.baseURL+path, body)
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, path, err)
	}
	if requestBody != nil {
		request.Header.Set("Content-Type", "application/json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := s.client.Do(request)
	if err != nil {
		t.Fatalf("perform %s %s request: %v", method, path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	return response.StatusCode, responseBody
}

func (s *integrationStack) rawRequest(t *testing.T, method, path string, body []byte, bearer string, headers map[string]string) (int, []byte) {
	t.Helper()
	request, err := http.NewRequestWithContext(context.Background(), method, s.baseURL+path, bytes.NewReader(body))
	if err != nil {
		t.Fatalf("build %s %s request: %v", method, path, err)
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := s.client.Do(request)
	if err != nil {
		t.Fatalf("perform %s %s request: %v", method, path, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read %s %s response: %v", method, path, err)
	}
	return response.StatusCode, responseBody
}

func newAdminSession(t *testing.T) (*integrationStack, store.User, string) {
	t.Helper()
	stack := newIntegrationStack(t)
	admin := seedPasswordUser(t, context.Background(), stack.database.pool, "admin", "admin-password")
	bootstrapTestAdmin(t, context.Background(), stack.database.pool, admin.ID)
	return stack, admin, loginUser(t, stack, admin.Username, "admin-password")
}

func decodeResponse(t *testing.T, body []byte, destination any) {
	t.Helper()
	if err := json.Unmarshal(body, destination); err != nil {
		t.Fatalf("decode JSON response %q: %v", string(body), err)
	}
}

func assertTokenPair(t *testing.T, pair tokenPair) {
	t.Helper()
	if pair.AccessToken == "" || pair.RefreshToken == "" || pair.TokenType != "Bearer" || pair.ExpiresIn <= 0 {
		t.Fatalf("invalid token pair: %+v", pair)
	}
}

func assertPermissionKeys(t *testing.T, response permissionsResponse, expected []string) {
	t.Helper()
	keys := make(map[string]bool, len(response.Grants))
	for _, grant := range response.Grants {
		keys[grant.Key] = true
	}
	for _, key := range expected {
		if !keys[key] {
			t.Fatalf("permissions response missing %q: %+v", key, response.Grants)
		}
	}
}

func quoteIdentifier(identifier string) string {
	return `"` + strings.ReplaceAll(identifier, `"`, `""`) + `"`
}
