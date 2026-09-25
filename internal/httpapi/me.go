package httpapi

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// MeHandlers contains the authenticated self-service handlers. The router is
// kept in httpapi so future /me resources can be mounted without coupling the
// HTTP routing package to authentication internals.
type MeHandlers struct {
	EnrollTOTP  http.HandlerFunc
	ConfirmTOTP http.HandlerFunc
	DeleteTOTP  http.HandlerFunc
}

// NewMeRouter constructs the authenticated self-service router. Only user
// bearer subjects are accepted; service subjects cannot act as a user.
func NewMeRouter(authMW func(http.Handler) http.Handler, handlers MeHandlers) chi.Router {
	router := chi.NewRouter()
	if authMW != nil {
		router.Use(authMW)
	}
	router.Use(requireMeSubject)
	router.Post("/me/totp/enroll", handlers.EnrollTOTP)
	router.Post("/me/totp/confirm", handlers.ConfirmTOTP)
	router.Delete("/me/totp", handlers.DeleteTOTP)
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
