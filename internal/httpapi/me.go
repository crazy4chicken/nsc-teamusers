package httpapi

import (
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
)

// MeHandlers contains the authenticated self-service handlers. The router is
// kept in httpapi so future /me resources can be mounted without coupling the
// HTTP routing package to authentication internals.
type MeHandlers struct {
	Profile                   http.HandlerFunc
	PatchProfile              http.HandlerFunc
	ChangePassword            http.HandlerFunc
	ListSessions              http.HandlerFunc
	DeleteSession             http.HandlerFunc
	EnrollTOTP                http.HandlerFunc
	ConfirmTOTP               http.HandlerFunc
	RegenerateBackupCodes     http.HandlerFunc
	DeleteTOTP                http.HandlerFunc
	BeginPasskeyRegistration  http.HandlerFunc
	FinishPasskeyRegistration http.HandlerFunc
	ListPasskeys              http.HandlerFunc
	DeletePasskey             http.HandlerFunc
}

// SessionResponse is the intentionally limited refresh-session representation
// returned by self-service and administrative session endpoints.
type SessionResponse struct {
	ID        string    `json:"id"`
	CreatedAt time.Time `json:"created_at"`
	ExpiresAt time.Time `json:"expires_at"`
}

// NewMeRouter constructs the authenticated self-service router. Only user
// bearer subjects are accepted; service subjects cannot act as a user.
func NewMeRouter(authMW func(http.Handler) http.Handler, handlers MeHandlers) chi.Router {
	router := chi.NewRouter()
	if authMW != nil {
		router.Use(authMW)
	}
	router.Use(requireMeSubject)
	router.Get("/me", handlers.Profile)
	router.Patch("/me", handlers.PatchProfile)
	router.Post("/me/password", handlers.ChangePassword)
	router.Get("/me/sessions", handlers.ListSessions)
	router.Delete("/me/sessions/{id}", handlers.DeleteSession)
	router.Post("/me/totp/enroll", handlers.EnrollTOTP)
	router.Post("/me/totp/confirm", handlers.ConfirmTOTP)
	router.Post("/me/totp/backup-codes", handlers.RegenerateBackupCodes)
	router.Delete("/me/totp", handlers.DeleteTOTP)
	router.Post("/me/passkeys/register/begin", handlers.BeginPasskeyRegistration)
	router.Post("/me/passkeys/register/finish", handlers.FinishPasskeyRegistration)
	router.Get("/me/passkeys", handlers.ListPasskeys)
	router.Delete("/me/passkeys/{credID}", handlers.DeletePasskey)
	return router
}

func requireMeSubject(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		subject, ok := SubjectFrom(r.Context())
		if !ok || subject.UserID == "" || subject.Kind != "user" {
			WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "an authenticated user subject is required")
			return
		}
		next.ServeHTTP(w, r)
	})
}
