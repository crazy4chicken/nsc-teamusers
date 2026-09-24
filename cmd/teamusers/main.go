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
)

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
		fmt.Fprintln(os.Stderr, "usage: teamusers <run|status|doctor> [flags]")
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
	default:
		fmt.Fprintf(os.Stderr, "unknown command %q; expected run, status, or doctor\n", command)
		os.Exit(2)
	}
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
	authzRoutes := authz.NewRouter(pool, authService.Middleware())
	adminRoutes := httpapi.NewAdminRouter(pool, auditWriter, authService.Middleware())
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
		events.NewDispatcher(pool, cfg, logger).Run(eventContext)
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
