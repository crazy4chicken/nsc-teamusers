package httpapi

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/chi/v5/middleware"
	"github.com/jackc/pgx/v5/pgxpool"

	"nsc-teamusers/internal/config"
)

// Server owns the HTTP lifecycle and the routes that are always available.
type Server struct {
	httpServer *http.Server
	router     chi.Router
	pool       *pgxpool.Pool
	listener   net.Listener
}

// NewServer constructs a chi router with the shared middleware stack and
// liveness/readiness endpoints. Additional application routers can be mounted
// before ListenAndServe is called.
func NewServer(cfg config.Config, pool *pgxpool.Pool) *Server {
	router := chi.NewRouter()
	router.Use(middleware.RequestID)
	router.Use(trustedRealIP)
	router.Use(middleware.Recoverer)
	router.Use(middleware.Timeout(30 * time.Second))

	server := &Server{router: router, pool: pool}
	router.Get("/healthz", server.healthz)
	router.Get("/readyz", server.readyz)
	server.httpServer = &http.Server{
		Addr:              net.JoinHostPort(cfg.ListenAddress, strconv.Itoa(cfg.ListenPort)),
		Handler:           router,
		ReadHeaderTimeout: 5 * time.Second,
	}
	return server
}

// Router returns the root router for mounting application routes.
func (s *Server) Router() chi.Router {
	return s.router
}

// Mount attaches a handler to this server's root router.
func (s *Server) Mount(pattern string, handler http.Handler) {
	s.router.Mount(pattern, handler)
}

// Mount attaches a handler to any chi router. It is useful to let later
// packages register their routers without depending on Server internals.
func Mount(router chi.Router, pattern string, handler http.Handler) {
	router.Mount(pattern, handler)
}

// Listen binds the configured address. The effective address may differ from
// the configured one when the port is 0 (leased/ephemeral); Addr reports it
// after Listen succeeds. Called implicitly by ListenAndServe when needed.
func (s *Server) Listen() error {
	listener, err := net.Listen("tcp", s.httpServer.Addr)
	if err != nil {
		return err
	}
	s.listener = listener
	return nil
}

// Addr reports the effective bound address after Listen, otherwise the
// configured address.
func (s *Server) Addr() string {
	if s.listener != nil {
		return s.listener.Addr().String()
	}
	return s.httpServer.Addr
}

// Handler returns the complete HTTP handler.
func (s *Server) Handler() http.Handler {
	return s.httpServer.Handler
}

// ListenAndServe binds (via Listen when not already bound) and starts
// accepting HTTP requests.
func (s *Server) ListenAndServe() error {
	if s.listener == nil {
		if err := s.Listen(); err != nil {
			return err
		}
	}
	return s.httpServer.Serve(s.listener)
}

// Shutdown stops accepting requests and waits for in-flight handlers to
// finish until ctx expires.
func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

// trustedRealIP accepts forwarded client addresses only from a loopback
// direct peer. Publicly reachable peers must not be allowed to forge rate
// limit and audit metadata through X-Forwarded-For.
func trustedRealIP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if remoteIP(r.RemoteAddr).IsLoopback() {
			forwarded := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-For"), ",")[0])
			if ip := remoteIP(forwarded); ip != nil {
				r.RemoteAddr = ip.String()
			}
		}
		next.ServeHTTP(w, r)
	})
}

func remoteIP(address string) net.IP {
	address = strings.TrimSpace(address)
	if host, _, err := net.SplitHostPort(address); err == nil {
		address = host
	}
	address = strings.Trim(address, "[]")
	return net.ParseIP(address)
}

func (s *Server) healthz(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]string{"status": "ok"})
}

func (s *Server) readyz(w http.ResponseWriter, r *http.Request) {
	if s.pool == nil {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	var result int
	if err := s.pool.QueryRow(r.Context(), "SELECT 1").Scan(&result); err != nil || result != 1 {
		writeJSON(w, http.StatusServiceUnavailable, map[string]string{"status": "not_ready"})
		return
	}
	writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
