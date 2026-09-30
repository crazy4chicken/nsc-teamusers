package httpapi_test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/authn"
	"teamusers/internal/config"
	"teamusers/internal/httpapi"
)

type failingBeginQuery struct {
	beginErr    error
	beginCalls  int
	queryCalls  int
}

func (q *failingBeginQuery) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	q.queryCalls++
	var tag pgconn.CommandTag
	return tag, errors.New("unexpected query during failed transaction")
}

func (q *failingBeginQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.queryCalls++
	return nil, errors.New("unexpected query during failed transaction")
}

func (q *failingBeginQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	q.queryCalls++
	return nil
}

func (q *failingBeginQuery) Begin(context.Context) (pgx.Tx, error) {
	q.beginCalls++
	return nil, q.beginErr
}

func TestRotateSigningKeyBeginFailureDiscardsPreparedFiles(t *testing.T) {
	keyDir := t.TempDir()
	query := &failingBeginQuery{beginErr: errors.New("database unavailable")}
	cfg := config.Config{
		ListenAddress: "127.0.0.1",
		LogLevel:      "info",
		KeyDir:        keyDir,
	}
	service, err := authn.New(authn.Deps{Config: cfg, Q: query})
	if err != nil {
		t.Fatalf("create authn service: %v", err)
	}
	activeBefore, err := os.ReadFile(filepath.Join(keyDir, "ACTIVE"))
	if err != nil {
		t.Fatalf("read initial ACTIVE marker: %v", err)
	}
	filesBefore := keyDirectoryFiles(t, keyDir)

	router := httpapi.NewAdminRouter(query, nil, nil, cfg, service)
	request := httptest.NewRequest(http.MethodPost, "/keys/rotate", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusInternalServerError {
		t.Fatalf("rotation status = %d, want %d", response.Code, http.StatusInternalServerError)
	}
	if query.beginCalls != 1 {
		t.Fatalf("transaction begin calls = %d, want 1", query.beginCalls)
	}
	if query.queryCalls != 0 {
		t.Fatalf("database query calls = %d, want none before a transaction begins", query.queryCalls)
	}

	activeAfter, err := os.ReadFile(filepath.Join(keyDir, "ACTIVE"))
	if err != nil || string(activeAfter) != string(activeBefore) {
		t.Fatalf("ACTIVE marker after failed rotation = %q, %v; want %q", activeAfter, err, activeBefore)
	}
	if filesAfter := keyDirectoryFiles(t, keyDir); !equalFileNames(filesAfter, filesBefore) {
		t.Fatalf("key files after failed rotation = %v, want %v", filesAfter, filesBefore)
	}
}

func TestRotateSigningKeyAlreadyInProgressReturnsConflict(t *testing.T) {
	keyDir := t.TempDir()
	query := &failingBeginQuery{}
	cfg := config.Config{
		ListenAddress: "127.0.0.1",
		LogLevel:      "info",
		KeyDir:        keyDir,
	}
	service, err := authn.New(authn.Deps{Config: cfg, Q: query})
	if err != nil {
		t.Fatalf("create authn service: %v", err)
	}
	kid, _, _, _, err := service.PrepareSigningKeyRotation()
	if err != nil {
		t.Fatalf("prepare first signing key rotation: %v", err)
	}
	t.Cleanup(func() {
		if err := service.RollbackSigningKeyRotation(kid); err != nil {
			t.Errorf("remove prepared signing key: %v", err)
		}
	})

	router := httpapi.NewAdminRouter(query, nil, nil, cfg, service)
	request := httptest.NewRequest(http.MethodPost, "/keys/rotate", nil)
	response := httptest.NewRecorder()
	router.ServeHTTP(response, request)
	if response.Code != http.StatusConflict {
		t.Fatalf("rotation status = %d, want %d", response.Code, http.StatusConflict)
	}
	if contentType := response.Header().Get("Content-Type"); contentType != "application/problem+json" {
		t.Fatalf("rotation content type = %q, want application/problem+json", contentType)
	}
	var problem httpapi.Problem
	if err := json.NewDecoder(response.Body).Decode(&problem); err != nil {
		t.Fatalf("decode rotation problem: %v", err)
	}
	if problem.Type != "about:blank" || problem.Title != "Conflict" || problem.Status != http.StatusConflict {
		t.Fatalf("rotation problem = %+v, want conflict problem", problem)
	}
	if query.beginCalls != 0 {
		t.Fatalf("transaction begin calls = %d, want none while rotation is already pending", query.beginCalls)
	}
}

func keyDirectoryFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read key directory: %v", err)
	}
	files := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			files = append(files, entry.Name())
		}
	}
	return files
}

func equalFileNames(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
