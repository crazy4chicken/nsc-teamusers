package httpapi

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"

	"teamusers/internal/config"
)

func TestFreshAuthTimeBoundaries(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	for _, testCase := range []struct {
		name     string
		authTime int64
		maxAge   time.Duration
		want     bool
	}{
		{name: "missing", authTime: 0, maxAge: 10 * time.Minute},
		{name: "exactly maximum age", authTime: now.Add(-10 * time.Minute).Unix(), maxAge: 10 * time.Minute, want: true},
		{name: "older than maximum age", authTime: now.Add(-10*time.Minute - time.Second).Unix(), maxAge: 10 * time.Minute},
		{name: "exactly future skew", authTime: now.Add(30 * time.Second).Unix(), maxAge: 10 * time.Minute, want: true},
		{name: "beyond future skew", authTime: now.Add(31 * time.Second).Unix(), maxAge: 10 * time.Minute},
		{name: "non-positive max age", authTime: now.Unix(), maxAge: 0},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := freshAuthTime(testCase.authTime, testCase.maxAge, now); got != testCase.want {
				t.Fatalf("freshAuthTime(%d, %s) = %t, want %t", testCase.authTime, testCase.maxAge, got, testCase.want)
			}
		})
	}
}

func TestSensitiveAdminMutationsRequireFreshAuthentication(t *testing.T) {
	staleAuthTime := time.Now().Add(-11 * time.Minute).Unix()
	authMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission := adminPermissionForPath(r.URL.Path)
			ctx := context.WithValue(r.Context(), freshAuthPermissionKey{}, permission)
			ctx = ContextWithSubject(ctx, Subject{UserID: "admin_test", Kind: "user", AuthTime: staleAuthTime})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := NewAdminRouter(freshAuthTestQ{}, nil, authMW, config.Config{}, nil)
	for _, testCase := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodDelete, path: "/users/user_test"},
		{method: http.MethodPost, path: "/users/user_test/disable"},
		{method: http.MethodPost, path: "/users/user_test/approve"},
		{method: http.MethodPost, path: "/users/user_test/credentials"},
		{method: http.MethodDelete, path: "/users/user_test/totp"},
		{method: http.MethodDelete, path: "/users/user_test/sessions"},
		{method: http.MethodDelete, path: "/users/user_test/sessions/session_test"},
		{method: http.MethodPatch, path: "/users/user_test", body: `{"status":"disabled"}`},
		{method: http.MethodPatch, path: "/users/user_test", body: `{"email":"new@example.test"}`},
		{method: http.MethodPost, path: "/users/batch", body: `{"ids":["user_test"],"op":"disable"}`},
		{method: http.MethodPut, path: "/groups/group_test/members"},
		{method: http.MethodPost, path: "/groups/group_test/members/batch"},
		{method: http.MethodPut, path: "/roles/role_test/permissions"},
		{method: http.MethodPost, path: "/bindings"},
		{method: http.MethodDelete, path: "/bindings/binding_test"},
		{method: http.MethodPost, path: "/policies/mfa"},
		{method: http.MethodPatch, path: "/policies/mfa/policy_test"},
		{method: http.MethodDelete, path: "/policies/mfa/policy_test"},
		{method: http.MethodPost, path: "/policies/password"},
		{method: http.MethodPatch, path: "/policies/password/policy_test"},
		{method: http.MethodDelete, path: "/policies/password/policy_test"},
		{method: http.MethodPost, path: "/keys/rotate"},
	} {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(testCase.body))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code != http.StatusForbidden || !strings.Contains(recorder.Body.String(), "step_up_required") {
				t.Fatalf("response = %d %s, want step_up_required 403", recorder.Code, recorder.Body.String())
			}
		})
	}
}

func TestAdminMutationsOutsideFreshAuthBoundaryRemainUnguarded(t *testing.T) {
	staleAuthTime := time.Now().Add(-11 * time.Minute).Unix()
	authMW := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			permission := adminPermissionForPath(r.URL.Path)
			ctx := context.WithValue(r.Context(), freshAuthPermissionKey{}, permission)
			ctx = ContextWithSubject(ctx, Subject{UserID: "admin_test", Kind: "user", AuthTime: staleAuthTime})
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
	router := NewAdminRouter(freshAuthTestQ{}, nil, authMW, config.Config{}, nil)
	for _, testCase := range []struct {
		method string
		path   string
		body   string
	}{
		{method: http.MethodPatch, path: "/users/user_test", body: `{"display_name":"Updated"}`},
		{method: http.MethodPatch, path: "/users/user_test", body: `{"status":"active"}`},
		{method: http.MethodPost, path: "/users/batch", body: `{"ids":[],"op":"enable"}`},
		{method: http.MethodPost, path: "/users", body: `{}`},
		{method: http.MethodPost, path: "/users/import"},
		{method: http.MethodDelete, path: "/roles/role_test"},
	} {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			request := httptest.NewRequest(testCase.method, testCase.path, strings.NewReader(testCase.body))
			recorder := httptest.NewRecorder()
			router.ServeHTTP(recorder, request)
			if recorder.Code == http.StatusForbidden && strings.Contains(recorder.Body.String(), "step_up_required") {
				t.Fatalf("response = %d %s, did not expect step_up_required", recorder.Code, recorder.Body.String())
			}
		})
	}
}

type freshAuthPermissionKey struct{}

type freshAuthTestQ struct{}

func (freshAuthTestQ) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	panic("fresh-auth route test did not expect a write")
}

func (freshAuthTestQ) Query(ctx context.Context, _ string, _ ...any) (pgx.Rows, error) {
	permission, ok := ctx.Value(freshAuthPermissionKey{}).(string)
	if !ok || permission == "" {
		return nil, context.Canceled
	}
	return &freshAuthPermissionRows{permission: permission}, nil
}

func (freshAuthTestQ) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("fresh-auth route test did not expect QueryRow")
}

type freshAuthPermissionRows struct {
	permission string
	available  bool
}

func (r *freshAuthPermissionRows) TypeMap() *pgtype.Map                         { return pgtype.NewMap() }
func (r *freshAuthPermissionRows) Close()                                       {}
func (r *freshAuthPermissionRows) Err() error                                   { return nil }
func (r *freshAuthPermissionRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *freshAuthPermissionRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *freshAuthPermissionRows) Next() bool {
	if r.available {
		return false
	}
	r.available = true
	return true
}
func (r *freshAuthPermissionRows) Scan(dest ...any) error {
	if len(dest) == 1 {
		if permission, ok := dest[0].(*string); ok {
			*permission = r.permission
		}
	}
	return nil
}
func (r *freshAuthPermissionRows) Values() ([]any, error) { return nil, nil }
func (r *freshAuthPermissionRows) RawValues() [][]byte    { return nil }
func (r *freshAuthPermissionRows) Conn() *pgx.Conn        { return nil }
