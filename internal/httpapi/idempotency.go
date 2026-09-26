package httpapi

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"teamusers/internal/store"
)

const maxIdempotencyResponseBytes = 64 << 10

// idempotencyMiddleware applies Idempotency-Key semantics to every POST that
// reaches the root handler. Requests without a key pass through unchanged.
// The scope hashes the raw Authorization header when present (the root
// middleware runs before authentication); otherwise it uses the resolved client IP.
func idempotencyMiddleware(pool *pgxpool.Pool) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		if pool == nil {
			return next
		}
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPost {
				next.ServeHTTP(w, r)
				return
			}
			key := strings.TrimSpace(r.Header.Get("Idempotency-Key"))
			if key == "" {
				next.ServeHTTP(w, r)
				return
			}

			var body []byte
			var err error
			if r.Body != nil {
				originalBody := r.Body
				body, err = io.ReadAll(originalBody)
				_ = originalBody.Close()
			}
			if err != nil {
				WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "request body could not be read")
				return
			}
			r.Body = io.NopCloser(bytes.NewReader(body))

			digest := sha256.Sum256(body)
			fingerprint := hex.EncodeToString(digest[:])
			scope := idempotencyScope(r)
			now := time.Now().UTC()
			record, claimed, err := store.ClaimIdempotency(r.Context(), pool, scope, key, fingerprint, now, now.Add(store.IdempotencyTTL))
			if err != nil {
				WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "idempotency store unavailable")
				return
			}
			if !claimed {
				if record.Fingerprint != fingerprint {
					WriteProblem(w, r, http.StatusUnprocessableEntity, "Idempotency Conflict", "idempotency_conflict")
					return
				}
				if record.Status == nil {
					WriteProblem(w, r, http.StatusConflict, "Idempotency In Progress", "idempotency_in_progress")
					return
				}
				writeIdempotencyReplay(w, *record.Status, record.Response)
				return
			}

			recorder := newIdempotencyResponseRecorder()
			released := false
			release := func() {
				if released {
					return
				}
				if err := store.DeleteIdempotency(r.Context(), pool, scope, key); err != nil {
					slog.Error("release idempotency claim failed", "scope", scope, "key", key, "error", err)
					return
				}
				released = true
			}
			defer func() {
				if !released {
					release()
				}
			}()

			next.ServeHTTP(recorder, r)
			status := recorder.status
			if status == 0 {
				status = http.StatusOK
			}
			if status >= 500 || status == http.StatusTooManyRequests || recorder.body.Len() > maxIdempotencyResponseBytes {
				release()
				writeIdempotencyResponse(w, recorder, status)
				return
			}
			if err := store.CompleteIdempotency(r.Context(), pool, scope, key, status, recorder.body.Bytes()); err != nil {
				release()
				WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "idempotency store unavailable")
				return
			}
			released = true
			writeIdempotencyResponse(w, recorder, status)
		})
	}
}

func idempotencyScope(r *http.Request) string {
	if authorization := r.Header.Get("Authorization"); authorization != "" {
		digest := sha256.Sum256([]byte(authorization))
		return hex.EncodeToString(digest[:])
	}
	if ip := remoteIP(r.RemoteAddr); ip != nil {
		return ip.String()
	}
	return strings.TrimSpace(r.RemoteAddr)
}

type idempotencyResponseRecorder struct {
	header http.Header
	body   bytes.Buffer
	status int
}

func newIdempotencyResponseRecorder() *idempotencyResponseRecorder {
	return &idempotencyResponseRecorder{header: make(http.Header)}
}

func (r *idempotencyResponseRecorder) Header() http.Header {
	return r.header
}

func (r *idempotencyResponseRecorder) WriteHeader(status int) {
	if r.status != 0 {
		return
	}
	r.status = status
}

func (r *idempotencyResponseRecorder) Write(data []byte) (int, error) {
	if r.status == 0 {
		r.WriteHeader(http.StatusOK)
	}
	return r.body.Write(data)
}

func writeIdempotencyResponse(w http.ResponseWriter, recorder *idempotencyResponseRecorder, status int) {
	for key, values := range recorder.header {
		w.Header()[key] = append([]string(nil), values...)
	}
	w.WriteHeader(status)
	if recorder.body.Len() > 0 {
		_, _ = w.Write(recorder.body.Bytes())
	}
}

func writeIdempotencyReplay(w http.ResponseWriter, status int, body []byte) {
	w.Header().Set("Idempotency-Replayed", "true")
	w.WriteHeader(status)
	if len(body) > 0 {
		_, _ = w.Write(body)
	}
}
