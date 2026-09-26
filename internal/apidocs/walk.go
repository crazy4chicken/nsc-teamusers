package apidocs

import (
	"context"
	"errors"
	"net/http"
	"os"
	"sync"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/config"
	"teamusers/internal/store"
)

// RouterBuilder constructs the complete application router for documentation.
type RouterBuilder func(config.Config, store.Q) (chi.Router, error)

var (
	builderMu sync.RWMutex
	builder   RouterBuilder

	operationsMu    sync.RWMutex
	operationSet    []Operation
	operationGroups [][]Operation
)

// RegisterRouterBuilder supplies the concrete application wiring without making
// the apidocs package import every handler package.
func RegisterRouterBuilder(next RouterBuilder) {
	if next == nil {
		return
	}
	builderMu.Lock()
	builder = next
	builderMu.Unlock()
}

// RegisterOperations records one handler package's operation metadata.
func RegisterOperations(ops []Operation) {
	operationsMu.Lock()
	operationGroups = append(operationGroups, ops)
	operationsMu.Unlock()
}

// SetOperations replaces registered metadata with an explicit aggregate.
func SetOperations(ops []Operation) {
	operationsMu.Lock()
	operationSet = append([]Operation(nil), ops...)
	operationsMu.Unlock()
}

// All explicitly aggregates handler-package operation metadata in order.
func All(groups ...[]Operation) []Operation {
	var total int
	for _, group := range groups {
		total += len(group)
	}
	all := make([]Operation, 0, total)
	for _, group := range groups {
		all = append(all, group...)
	}
	return all
}

// BuildRouter constructs the documentation router using the runtime wiring.
func BuildRouter(cfg config.Config, q store.Q) (chi.Router, error) {
	if q == nil {
		q = fakeQ{}
	}
	builderMu.RLock()
	current := builder
	builderMu.RUnlock()
	if current == nil {
		return nil, errors.New("apidocs router builder is not registered")
	}
	return current(cfg, q)
}

// Operations builds the router and collects its registered metadata.
func Operations() ([]Operation, error) {
	keyDir, err := os.MkdirTemp("", "teamusers-apidocs-")
	if err != nil {
		return nil, err
	}
	defer os.RemoveAll(keyDir)
	cfg := config.Config{
		ListenAddress:    "127.0.0.1:0",
		KeyDir:           keyDir,
		WebAuthnRPID:     "localhost",
		WebAuthnOrigin:   "http://localhost",
		LogLevel:         "info",
		RegistrationMode: "closed",
	}
	router, err := BuildRouter(cfg, fakeQ{})
	if err != nil {
		return nil, err
	}
	operationsMu.RLock()
	metadata := append([]Operation(nil), operationSet...)
	if len(metadata) == 0 {
		groups := make([][]Operation, len(operationGroups))
		copy(groups, operationGroups)
		metadata = All(groups...)
	}
	operationsMu.RUnlock()
	return collect(router, metadata)
}

// WithRoutes keeps the runtime root handler while exposing child route trees
// to chi.Walk. The production server uses one dispatch mount; documentation
// needs the mounted child routes to be visible to route discovery.
func WithRoutes(root chi.Router, children ...chi.Router) (chi.Router, error) {
	routes := make([]chi.Route, 0)
	if root != nil {
		err := chi.Walk(root, func(method, path string, handler http.Handler, _ ...func(http.Handler) http.Handler) error {
			if path == "/" || path == "/*" {
				return nil
			}
			routes = append(routes, chi.Route{
				Pattern:  path,
				Handlers: map[string]http.Handler{method: handler},
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, child := range children {
		if child == nil {
			continue
		}
		err := chi.Walk(child, func(method, path string, handler http.Handler, _ ...func(http.Handler) http.Handler) error {
			routes = append(routes, chi.Route{
				Pattern:  path,
				Handlers: map[string]http.Handler{method: handler},
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return &routeView{Router: root, routes: routes}, nil
}

type routeView struct {
	chi.Router
	routes []chi.Route
}

func (r *routeView) Routes() []chi.Route { return r.routes }

type fakeQ struct{}

var errFakeQ = errors.New("documentation fake query handle")

func (fakeQ) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.CommandTag{}, errFakeQ
}

func (fakeQ) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errFakeQ
}

func (fakeQ) QueryRow(context.Context, string, ...any) pgx.Row {
	return fakeRow{}
}

type fakeRow struct{}

func (fakeRow) Scan(...any) error { return errFakeQ }
