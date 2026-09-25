package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/jackc/pgx/v5"
	_ "github.com/jackc/pgx/v5/stdlib"
	"github.com/pressly/goose/v3"

	"teamusers/internal/audit"
	"teamusers/internal/authn"
	"teamusers/internal/authz"
	"teamusers/internal/config"
	"teamusers/internal/events"
	"teamusers/internal/httpapi"
	"teamusers/internal/store"
	"teamusers/migrations"
)

const (
	version = "dev"

	migrationAdvisoryKey = "teamusers:migrations"
	migrationTimeout     = 2 * time.Minute
	shutdownTimeout      = 10 * time.Second
	doctorTimeout        = 15 * time.Second
	bootstrapTimeout     = 15 * time.Second
)

var bootstrapAdminPermissions = [...]struct {
	key         string
	description string
}{
	{key: "iam:users:any", description: "Manage users"},
	{key: "iam:teams:any", description: "Manage teams"},
	{key: "iam:groups:any", description: "Manage groups"},
	{key: "iam:roles:any", description: "Manage roles"},
	{key: "iam:permissions:any", description: "Manage permissions"},
	{key: "iam:bindings:any", description: "Manage role bindings"},
	{key: "iam:audit:any", description: "Read the audit log"},
	{key: "iam:sessions:any", description: "Manage user sessions"},
}

type statusOutput struct {
	Version string        `json:"version"`
	Config  config.Config `json:"config"`
}

type checkOutput struct {
	OK              bool   `json:"ok"`
	Error           string `json:"error,omitempty"`
	Version         int64  `json:"version,omitempty"`
	ExpectedVersion int64  `json:"expected_version,omitempty"`
}

type doctorOutput struct {
	Version    string        `json:"version"`
	Config     config.Config `json:"config"`
	Database   checkOutput   `json:"database"`
	Migrations checkOutput   `json:"migrations"`
	KeyDir     checkOutput   `json:"key_dir"`
	OK         bool          `json:"ok"`
	Error      string        `json:"error,omitempty"`
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintln(os.Stderr, "usage: teamusers <run|status|doctor|bootstrap-admin> [flags]")
		os.Exit(2)
	}

	command := os.Args[1]
	args := os.Args[2:]
	switch command {
	case "run":
		cfg, err := config.Load(args...)
		if err == nil {
			err = cfg.ValidateFor("run")
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := run(cfg); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "status":
		cfg, err := config.Load(args...)
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(2)
		}
		if err := writeJSON(os.Stdout, statusOutput{Version: version, Config: cfg.Redacted()}); err != nil {
			fmt.Fprintln(os.Stderr, err)
			os.Exit(1)
		}
	case "doctor":
		if !doctor(args...) {
			os.Exit(1)
		}
	case "bootstrap-admin":
		username, configArgs, err := parseBootstrapAdminArgs(args)
		if err == nil {
			var cfg config.Config
			cfg, err = config.Load(configArgs...)
			if err == nil {
				err = cfg.ValidateFor("bootstrap-admin")
			}
			if err == nil {
				err = runBootstrapAdmin(cfg, username)
			}
		}
		if err != nil {
			fmt.Fprintln(os.Stderr, err)
			if strings.HasPrefix(err.Error(), "bootstrap-admin: ") {
				os.Exit(1)
			}
			os.Exit(2)
		}
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; expected run, status, doctor, or bootstrap-admin\n", command)
		os.Exit(2)
	}
}

func parseBootstrapAdminArgs(args []string) (string, []string, error) {
	var username string
	configArgs := make([]string, 0, len(args))
	for i := 0; i < len(args); i++ {
		arg := args[i]
		switch {
		case arg == "--username":
			if i+1 >= len(args) || strings.TrimSpace(args[i+1]) == "" {
				return "", nil, errors.New("bootstrap-admin: --username requires a value")
			}
			username = strings.TrimSpace(args[i+1])
			i++
		case strings.HasPrefix(arg, "--username="):
			username = strings.TrimSpace(strings.TrimPrefix(arg, "--username="))
			if username == "" {
				return "", nil, errors.New("bootstrap-admin: --username requires a value")
			}
		default:
			configArgs = append(configArgs, arg)
		}
	}
	if username == "" {
		return "", nil, errors.New("bootstrap-admin: --username is required")
	}
	return username, configArgs, nil
}

func runBootstrapAdmin(cfg config.Config, username string) error {
	ctx, cancel := context.WithTimeout(context.Background(), bootstrapTimeout)
	defer cancel()
	pool, err := store.NewPool(ctx, cfg.ConnectionString)
	if err != nil {
		return fmt.Errorf("bootstrap-admin: connect PostgreSQL: %w", err)
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return fmt.Errorf("bootstrap-admin: ping PostgreSQL: %w", err)
	}
	result, err := bootstrapAdmin(ctx, pool, username)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stdout, "bootstrap-admin: ensured %d permission keys for %s (%d newly added)\n", len(bootstrapAdminPermissions), result.Username, result.PermissionsAdded)
	if result.RoleCreated {
		fmt.Fprintln(os.Stdout, "bootstrap-admin: created role iam-admin")
	} else {
		fmt.Fprintln(os.Stdout, "bootstrap-admin: role iam-admin already exists")
	}
	if result.RolePermissionsAdded > 0 {
		fmt.Fprintf(os.Stdout, "bootstrap-admin: added %d permissions to iam-admin\n", result.RolePermissionsAdded)
	} else {
		fmt.Fprintln(os.Stdout, "bootstrap-admin: iam-admin already held all permissions")
	}
	if result.BindingCreated {
		fmt.Fprintf(os.Stdout, "bootstrap-admin: bound %s to iam-admin\n", result.Username)
	} else {
		fmt.Fprintf(os.Stdout, "bootstrap-admin: %s already bound to iam-admin\n", result.Username)
	}
	return nil
}

type bootstrapAdminResult struct {
	Username             string
	PermissionsAdded     int
	RoleCreated          bool
	RolePermissionsAdded int
	BindingCreated       bool
}

func bootstrapAdmin(ctx context.Context, q store.Q, username string) (bootstrapAdminResult, error) {
	username = strings.TrimSpace(username)
	if username == "" {
		return bootstrapAdminResult{}, errors.New("bootstrap-admin: --username is required")
	}
	user, err := store.GetUserByUsername(ctx, q, username)
	if errors.Is(err, pgx.ErrNoRows) {
		return bootstrapAdminResult{}, fmt.Errorf("bootstrap-admin: user %q was not found", username)
	}
	if err != nil {
		return bootstrapAdminResult{}, fmt.Errorf("bootstrap-admin: look up user %q: %w", username, err)
	}
	result := bootstrapAdminResult{Username: user.Username}
	err = store.WithAdminTx(ctx, q, func(ctx context.Context, tx store.Tx) error {
		for _, permission := range bootstrapAdminPermissions {
			tag, err := tx.Exec(ctx, `
                INSERT INTO permissions (key, description, registered_by)
                VALUES ($1, $2, $3)
                ON CONFLICT (key) DO NOTHING`, permission.key, permission.description, "teamusers-bootstrap-admin")
			if err != nil {
				return err
			}
			result.PermissionsAdded += int(tag.RowsAffected())
		}
		if result.PermissionsAdded > 0 {
			if _, err := store.BumpPermissionRegistryPermVer(ctx, tx); err != nil {
				return err
			}
		}

		var roleID string
		err := tx.QueryRow(ctx, `
            SELECT id FROM roles
            WHERE team_id IS NULL AND name = $1
            ORDER BY id LIMIT 1`, "iam-admin").Scan(&roleID)
		switch {
		case errors.Is(err, pgx.ErrNoRows):
			roleID = store.NewID()
			if _, err := tx.Exec(ctx, `
                INSERT INTO roles (id, team_id, name) VALUES ($1, NULL, $2)`, roleID, "iam-admin"); err != nil {
				return err
			}
			result.RoleCreated = true
		case err != nil:
			return err
		}

		for _, permission := range bootstrapAdminPermissions {
			tag, err := tx.Exec(ctx, `
                INSERT INTO role_permissions (role_id, permission_key)
                VALUES ($1, $2)
                ON CONFLICT (role_id, permission_key) DO NOTHING`, roleID, permission.key)
			if err != nil {
				return err
			}
			result.RolePermissionsAdded += int(tag.RowsAffected())
		}

		var bound bool
		if err := tx.QueryRow(ctx, `
            SELECT EXISTS(
                SELECT 1 FROM role_bindings
                WHERE role_id = $1 AND subject_kind = 'user' AND subject_id = $2
            )`, roleID, user.ID).Scan(&bound); err != nil {
			return err
		}
		if !bound {
			if _, err := tx.Exec(ctx, `
                INSERT INTO role_bindings (id, team_id, role_id, subject_kind, subject_id)
                VALUES ($1, NULL, $2, 'user', $3)`, store.NewID(), roleID, user.ID); err != nil {
				return err
			}
			result.BindingCreated = true
		}
		if result.RolePermissionsAdded > 0 || result.BindingCreated {
			_, err := store.BumpUserPermVer(ctx, tx, user.ID)
			return err
		}
		return nil
	})
	if err != nil {
		return bootstrapAdminResult{}, fmt.Errorf("bootstrap-admin: provision %q: %w", username, err)
	}
	return result, nil
}

func run(cfg config.Config) error {
	logger := slog.New(slog.NewJSONHandler(os.Stderr, &slog.HandlerOptions{Level: cfg.SlogLevel()}))
	slog.SetDefault(logger)

	signalContext, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	migrationContext, cancelMigration := context.WithTimeout(signalContext, migrationTimeout)
	err := applyMigrations(migrationContext, cfg.ConnectionString)
	cancelMigration()
	if err != nil {
		return fmt.Errorf("apply migrations: %w", err)
	}

	pool, err := store.NewPool(signalContext, cfg.ConnectionString)
	if err != nil {
		return err
	}
	defer pool.Close()
	if err := pool.Ping(signalContext); err != nil {
		return fmt.Errorf("ping PostgreSQL: %w", err)
	}

	server := httpapi.NewServer(cfg, pool)
	if err := server.Listen(); err != nil {
		return fmt.Errorf("bind listen address: %w", err)
	}

	auditWriter := audit.NewWriter()
	authService, err := authn.New(authn.Dependencies{
		Config: cfg, Q: pool, Pool: pool, Audit: auditWriter, Context: signalContext,
	})
	if err != nil {
		return fmt.Errorf("initialize authentication: %w", err)
	}
	authRoutes := authService.Routes()
	meRoutes := authService.MeRoutes()
	authzRoutes := authz.NewRouter(pool, authService.Middleware())
	adminRoutes := httpapi.NewAdminRouter(pool, auditWriter, authService.Middleware(), cfg)
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
	eventContext, cancelEvents := context.WithCancel(signalContext)
	defer cancelEvents()
	var eventWorkers sync.WaitGroup
	eventWorkers.Add(2)
	go func() {
		defer eventWorkers.Done()
		events.NewRelay(pool, cfg, logger).Run(eventContext)
	}()
	go func() {
		defer eventWorkers.Done()
		events.NewNotifier(pool, cfg, logger).Run(eventContext)
	}()
	waitForEvents := func(waitContext context.Context) {
		cancelEvents()
		done := make(chan struct{})
		go func() {
			eventWorkers.Wait()
			close(done)
		}()
		select {
		case <-done:
		case <-waitContext.Done():
			logger.Warn("event workers did not stop before shutdown deadline")
		}
	}

	serverErrors := make(chan error, 1)
	go func() {
		err := server.ListenAndServe()
		if errors.Is(err, http.ErrServerClosed) {
			err = nil
		}
		serverErrors <- err
	}()
	logger.Info("HTTP server serving", "address", server.Addr(), "version", version)

	select {
	case err := <-serverErrors:
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
		waitForEvents(shutdownContext)
		cancelShutdown()
		return err
	case <-signalContext.Done():
		logger.Info("shutdown requested")
		shutdownContext, cancelShutdown := context.WithTimeout(context.Background(), shutdownTimeout)
		if err := server.Shutdown(shutdownContext); err != nil {
			waitForEvents(shutdownContext)
			cancelShutdown()
			return fmt.Errorf("shutdown HTTP server: %w", err)
		}
		waitForEvents(shutdownContext)
		cancelShutdown()
		return nil
	}
}

func applyMigrations(ctx context.Context, connectionString string) error {
	db, err := goose.OpenDBWithDriver("pgx", connectionString)
	if err != nil {
		return err
	}
	defer db.Close()
	db.SetMaxOpenConns(1)
	db.SetMaxIdleConns(1)
	if err := db.PingContext(ctx); err != nil {
		return err
	}

	if _, err := db.ExecContext(ctx,
		"SELECT pg_advisory_lock(hashtextextended($1, 0))", migrationAdvisoryKey); err != nil {
		return fmt.Errorf("acquire migration advisory lock: %w", err)
	}
	defer func() {
		_, _ = db.ExecContext(context.Background(),
			"SELECT pg_advisory_unlock(hashtextextended($1, 0))", migrationAdvisoryKey)
	}()

	if err := goose.SetDialect("postgres"); err != nil {
		return err
	}
	goose.SetBaseFS(migrations.FS)
	goose.SetVerbose(false)
	if err := goose.UpContext(ctx, db, "."); err != nil {
		return err
	}
	return nil
}

func doctor(args ...string) bool {
	cfg, err := config.Load(args...)
	if err != nil {
		return writeDoctorFailure(err)
	}
	if err := cfg.ValidateFor("doctor"); err != nil {
		return writeDoctorFailureWithConfig(cfg, err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), doctorTimeout)
	defer cancel()

	report := doctorOutput{
		Version: version,
		Config:  cfg.Redacted(),
		KeyDir:  checkKeyDir(cfg.KeyDir),
	}
	report.Database = checkDatabase(ctx, cfg.ConnectionString)
	report.Migrations = checkMigrations(ctx, cfg.ConnectionString)
	report.OK = report.Database.OK && report.Migrations.OK && report.KeyDir.OK
	if err := writeJSON(os.Stdout, report); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return false
	}
	return report.OK
}

func checkDatabase(ctx context.Context, connectionString string) checkOutput {
	pool, err := store.NewPool(ctx, connectionString)
	if err != nil {
		return checkOutput{Error: err.Error()}
	}
	defer pool.Close()
	if err := pool.Ping(ctx); err != nil {
		return checkOutput{Error: err.Error()}
	}
	return checkOutput{OK: true}
}

func checkMigrations(ctx context.Context, connectionString string) checkOutput {
	expected := expectedMigrationVersion()
	db, err := goose.OpenDBWithDriver("pgx", connectionString)
	if err != nil {
		return checkOutput{ExpectedVersion: expected, Error: err.Error()}
	}
	defer db.Close()
	if err := db.PingContext(ctx); err != nil {
		return checkOutput{ExpectedVersion: expected, Error: err.Error()}
	}
	if err := goose.SetDialect("postgres"); err != nil {
		return checkOutput{ExpectedVersion: expected, Error: err.Error()}
	}
	goose.SetBaseFS(migrations.FS)
	current, err := goose.GetDBVersionContext(ctx, db)
	if err != nil {
		return checkOutput{ExpectedVersion: expected, Error: err.Error()}
	}
	result := checkOutput{Version: current, ExpectedVersion: expected, OK: current == expected}
	if !result.OK {
		result.Error = fmt.Sprintf("database migration version is %d, expected %d", current, expected)
	}
	return result
}

// expectedMigrationVersion derives the newest migration version from the
// embedded migrations directory so doctor never depends on a hand-maintained
// constant.
func expectedMigrationVersion() int64 {
	entries, err := migrations.FS.ReadDir(".")
	if err != nil {
		return -1
	}
	var latest int64
	for _, entry := range entries {
		name := entry.Name()
		separator := strings.IndexByte(name, '_')
		if separator <= 0 {
			continue
		}
		version, err := strconv.ParseInt(name[:separator], 10, 64)
		if err == nil && version > latest {
			latest = version
		}
	}
	return latest
}

func checkKeyDir(keyDir string) checkOutput {
	if err := os.MkdirAll(keyDir, 0o700); err != nil {
		return checkOutput{Error: err.Error()}
	}
	file, err := os.CreateTemp(keyDir, ".teamusers-write-*")
	if err != nil {
		return checkOutput{Error: err.Error()}
	}
	name := file.Name()
	defer os.Remove(name)
	if _, err := file.WriteString("ok"); err != nil {
		_ = file.Close()
		return checkOutput{Error: err.Error()}
	}
	if err := file.Close(); err != nil {
		return checkOutput{Error: err.Error()}
	}
	return checkOutput{OK: true}
}

func writeDoctorFailure(err error) bool {
	return writeDoctorFailureWithConfig(config.Config{}, err)
}

func writeDoctorFailureWithConfig(cfg config.Config, err error) bool {
	report := doctorOutput{Version: version, Config: cfg.Redacted(), Error: err.Error()}
	if writeErr := writeJSON(os.Stdout, report); writeErr != nil {
		fmt.Fprintln(os.Stderr, writeErr)
	}
	return false
}

func writeJSON(dst *os.File, value any) error {
	encoder := json.NewEncoder(dst)
	encoder.SetEscapeHTML(false)
	return encoder.Encode(value)
}
