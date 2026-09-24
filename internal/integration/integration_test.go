package integration

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

func TestAuthLifecycle(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()

	admin := seedPasswordUser(t, ctx, stack.database.pool, "admin", "admin-password")

	status, _ := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": admin.Username,
		"password": "wrong-password",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong password status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": admin.Username,
		"password": "admin-password",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var login tokenPair
	decodeResponse(t, body, &login)
	assertTokenPair(t, login)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var rotated tokenPair
	decodeResponse(t, body, &rotated)
	assertTokenPair(t, rotated)

	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": login.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("replayed refresh status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": rotated.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("family refresh after replay status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/.well-known/jwks.json", nil, "")
	if status != http.StatusOK {
		t.Fatalf("JWKS status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var jwks jwksResponse
	decodeResponse(t, body, &jwks)
	if len(jwks.Keys) == 0 {
		t.Fatal("JWKS response has no keys")
	}

	status, _ = stack.jsonRequest(t, http.MethodGet, "/users", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("admin request without token status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users", nil, login.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("admin request with token status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{
		"kind": "service",
	}, login.AccessToken)
	if status != http.StatusCreated {
		t.Fatalf("service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	if credential.ClientID != admin.Username || credential.ClientSecret == "" {
		t.Fatalf("service credential response = %+v, want client id and secret", credential)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("client credentials status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	assertTokenPair(t, servicePair)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/introspect", map[string]string{
		"token": servicePair.AccessToken,
	}, servicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("service introspection status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var introspection introspectionResponse
	decodeResponse(t, body, &introspection)
	if !introspection.Active || introspection.Kind != "service" || introspection.Subject != admin.ID {
		t.Fatalf("service introspection = %+v, want active service subject %s", introspection, admin.ID)
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/introspect", map[string]string{
		"token": servicePair.AccessToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("introspection without token status = %d, want %d", status, http.StatusUnauthorized)
	}
}

func TestAuthzEndToEnd(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()

	admin := seedPasswordUser(t, ctx, stack.database.pool, "admin", "admin-password")
	adminToken := loginUser(t, stack, admin.Username, "admin-password")

	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "alice",
		"password": "alice-password",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("target user creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var target userResponse
	decodeResponse(t, body, &target)
	if target.ID == "" {
		t.Fatal("target user response has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("admin service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id":     credential.ClientID,
		"client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("admin service login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	assertTokenPair(t, servicePair)
	serviceToken := servicePair.AccessToken

	status, body = stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "orders",
		"name": "Orders",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("team creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	if team.ID == "" {
		t.Fatal("team response has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{
		"team_id": team.ID,
		"name":    "operators",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("group creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)
	if group.ID == "" {
		t.Fatal("group response has no id")
	}

	for _, key := range []string{"order:read:team", "order:write:team", "doc:read:own"} {
		status, body = stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key":           key,
			"description":   "integration permission",
			"registered_by": admin.ID,
		}, serviceToken)
		if status != http.StatusCreated {
			t.Fatalf("permission %s status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "operator",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("role creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	if role.ID == "" {
		t.Fatal("role response has no id")
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"order:read:team", "order:write:team", "doc:read:own"},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"team_id":      team.ID,
		"role_id":      role.ID,
		"subject_kind": "group",
		"subject_id":   group.ID,
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("group binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPut, "/groups/"+group.ID+"/members", map[string]string{
		"user_id": target.ID,
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("group membership status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/authz/permissions/"+target.ID, nil, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("permissions endpoint status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var permissions permissionsResponse
	decodeResponse(t, body, &permissions)
	assertPermissionKeys(t, permissions, []string{"order:read:team", "order:write:team", "doc:read:own"})

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:read:team",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("allow check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var check checkResponse
	decodeResponse(t, body, &check)
	if !check.Allow {
		t.Fatalf("order read check = %+v, want allow", check)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:delete:any",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("deny check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("order delete check allowed an ungranted permission")
	}

	// Remove the unconditional document grant before exercising the conditional
	// direct grant; otherwise the group grant would make the negative ABAC case
	// indistinguishable from a successful condition evaluation.
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": []string{"order:read:team", "order:write:team"},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("role permission narrowing status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/roles", map[string]string{
		"team_id": team.ID,
		"name":    "document-owner",
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("conditional role creation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var conditionalRole roleResponse
	decodeResponse(t, body, &conditionalRole)

	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+conditionalRole.ID+"/permissions", map[string]any{
		"permission_keys": []string{"doc:read:own"},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("conditional role permissions status = %d, want %d: %s", status, http.StatusOK, body)
	}

	condition := "resource.owner_id == subject.id"
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"team_id":      team.ID,
		"role_id":      conditionalRole.ID,
		"subject_kind": "user",
		"subject_id":   target.ID,
		"condition":    condition,
	}, serviceToken)
	if status != http.StatusCreated {
		t.Fatalf("direct conditional binding status = %d, want %d: %s", status, http.StatusCreated, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "doc:read:own",
		"context": map[string]any{
			"resource": map[string]string{"owner_id": target.ID, "team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("matching ABAC check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if !check.Allow {
		t.Fatal("matching ABAC check denied the owner")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "doc:read:own",
		"context": map[string]any{
			"resource": map[string]string{"owner_id": admin.ID, "team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("non-matching ABAC check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("non-matching ABAC check allowed a different owner")
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+target.ID+"/disable", nil, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("disable user status = %d, want %d: %s", status, http.StatusOK, body)
	}

	status, _ = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "alice",
		"password": "alice-password",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("disabled user login status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/authz/check", map[string]any{
		"subject":    target.ID,
		"permission": "order:read:team",
		"context": map[string]any{
			"resource": map[string]string{"team_id": team.ID},
		},
	}, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("disabled authorization check status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &check)
	if check.Allow {
		t.Fatal("disabled user authorization check allowed access")
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/audit", nil, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("audit endpoint status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var auditLog auditResponse
	decodeResponse(t, body, &auditLog)
	if len(auditLog.Items) == 0 {
		t.Fatal("audit endpoint returned no mutation entries")
	}
	foundAction := false
	for _, entry := range auditLog.Items {
		if entry.Action == "team.created" || entry.Action == "permission.registered" || entry.Action == "user.disabled" {
			foundAction = true
			break
		}
	}
	if !foundAction {
		t.Fatalf("audit entries contain no expected mutation action: %+v", auditLog.Items)
	}
}

func newIntegrationStack(t *testing.T) *integrationStack {
	t.Helper()
	database := newIntegrationDatabase(t)
	ctx, cancel := context.WithCancel(context.Background())

	cfg := config.Config{
		ConnectionString: database.connectionString,
		ListenAddress:    "127.0.0.1",
		ListenPort:       0,
		LogLevel:         "error",
		KeyDir:           t.TempDir(),
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
	authzRoutes := authz.NewRouter(database.pool, authService.Middleware())
	adminRoutes := httpapi.NewAdminRouter(database.pool, auditWriter, authService.Middleware())
	server.Mount("/", http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.HasPrefix(r.URL.Path, "/authz/") || r.URL.Path == "/authz" {
			authzRoutes.ServeHTTP(w, r)
			return
		}
		if strings.HasPrefix(r.URL.Path, "/auth/") || r.URL.Path == "/.well-known/jwks.json" {
			authRoutes.ServeHTTP(w, r)
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
