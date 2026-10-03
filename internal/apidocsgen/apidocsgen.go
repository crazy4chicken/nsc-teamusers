package apidocsgen

import (
	"context"
	"errors"
	"os"
	"sync"

	"github.com/crazy4chicken/nsc-teamusers/apidocs/go"
	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/config"
	"teamusers/internal/store"
)

// RouterBuilder constructs the complete application router for documentation.
type RouterBuilder func(config.Config, store.Q) (chi.Router, error)

// RouterChildBuilder constructs a package-owned child router for route discovery.
type RouterChildBuilder func(config.Config, store.Q) (chi.Router, error)

var (
	builderMu           sync.RWMutex
	builder             RouterBuilder
	routerChildBuilders []RouterChildBuilder
)

// RegisterRouterBuilder supplies the concrete application wiring without making
// this package import every handler package.
func RegisterRouterBuilder(next RouterBuilder) {
	if next == nil {
		return
	}
	builderMu.Lock()
	builder = next
	builderMu.Unlock()
}

// RegisterRouterChildBuilder adds a package-owned child router to the
// documentation route walk.
func RegisterRouterChildBuilder(next RouterChildBuilder) {
	if next == nil {
		return
	}
	builderMu.Lock()
	routerChildBuilders = append(routerChildBuilders, next)
	builderMu.Unlock()
}

// BuildRouter constructs the documentation router using the runtime wiring.
func BuildRouter(cfg config.Config, q store.Q) (chi.Router, error) {
	if q == nil {
		q = fakeQ{}
	}
	builderMu.RLock()
	current := builder
	childBuilders := append([]RouterChildBuilder(nil), routerChildBuilders...)
	builderMu.RUnlock()
	if current == nil {
		return nil, errors.New("apidocs router builder is not registered")
	}
	router, err := current(cfg, q)
	if err != nil {
		return nil, err
	}
	children := make([]chi.Router, 0, len(childBuilders))
	for _, buildChild := range childBuilders {
		child, err := buildChild(cfg, q)
		if err != nil {
			return nil, err
		}
		children = append(children, child)
	}
	return apidocs.WithRoutes(router, children...)
}

// Operations builds the router and collects its supplied metadata.
func Operations(metadata []apidocs.Operation, deriver apidocs.PermissionDeriver) ([]apidocs.Operation, error) {
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
	return apidocs.Collect(router, metadata, deriver)
}

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
