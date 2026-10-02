package httpapi

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestImpersonatedMeRouterAllowsOnlyDocumentedReads(t *testing.T) {
	respond := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := Subject{UserID: "target", Kind: "user", Impersonated: true, ActorID: "admin"}
			next.ServeHTTP(w, r.WithContext(ContextWithSubject(r.Context(), subject)))
		})
	}
	router := NewMeRouter(auth, MeHandlers{
		Profile:                   respond,
		Permissions:               respond,
		PasswordPolicy:            respond,
		PatchProfile:              respond,
		ChangePassword:            respond,
		ChangeEmail:               respond,
		ConfirmEmailChange:        respond,
		DeleteProfile:             respond,
		ExportProfile:             respond,
		ListSessions:              respond,
		ListActivity:              respond,
		DeleteSession:             respond,
		EnrollTOTP:                respond,
		ConfirmTOTP:               respond,
		RegenerateBackupCodes:     respond,
		DeleteTOTP:                respond,
		BeginPasskeyRegistration:  respond,
		FinishPasskeyRegistration: respond,
		ListPasskeys:              respond,
		DeletePasskey:             respond,
	})

	for _, path := range []string{
		"/me",
		"/me/password-policy",
		"/me/sessions",
		"/me/activity",
		"/me/export",
	} {
		t.Run("read "+path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, path, nil))
			if response.Code != http.StatusNoContent {
				t.Fatalf("GET %s status = %d, want %d: %s", path, response.Code, http.StatusNoContent, response.Body.String())
			}
		})
	}

	for _, tc := range []struct {
		method string
		path   string
	}{
		{http.MethodPatch, "/me"},
		{http.MethodPost, "/me/password"},
		{http.MethodPost, "/me/email"},
		{http.MethodPost, "/me/email/confirm"},
		{http.MethodDelete, "/me"},
		{http.MethodDelete, "/me/sessions/session-id"},
		{http.MethodPost, "/me/totp/enroll"},
		{http.MethodPost, "/me/totp/confirm"},
		{http.MethodPost, "/me/totp/backup-codes"},
		{http.MethodDelete, "/me/totp"},
		{http.MethodPost, "/me/passkeys/register/begin"},
		{http.MethodPost, "/me/passkeys/register/finish"},
		{http.MethodDelete, "/me/passkeys/credential-id"},
		{http.MethodGet, "/me/passkeys"},
		{http.MethodGet, "/me/permissions"},
	} {
		t.Run(tc.method+" "+tc.path, func(t *testing.T) {
			response := httptest.NewRecorder()
			router.ServeHTTP(response, httptest.NewRequest(tc.method, tc.path, nil))
			if response.Code != http.StatusForbidden || !strings.Contains(response.Body.String(), "impersonation_forbidden") {
				t.Fatalf("%s %s response = %d %s, want impersonation_forbidden 403", tc.method, tc.path, response.Code, response.Body.String())
			}
		})
	}
}

func TestMeRouterRegistersPermissionsRoute(t *testing.T) {
	auth := func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			subject := Subject{UserID: "current-user", Kind: "user"}
			next.ServeHTTP(w, r.WithContext(ContextWithSubject(r.Context(), subject)))
		})
	}
	router := NewMeRouter(auth, MeHandlers{
		Permissions: func(w http.ResponseWriter, _ *http.Request) {
			w.WriteHeader(http.StatusNoContent)
		},
	})
	response := httptest.NewRecorder()
	router.ServeHTTP(response, httptest.NewRequest(http.MethodGet, "/me/permissions", nil))
	if response.Code != http.StatusNoContent {
		t.Fatalf("GET /me/permissions status = %d, want %d", response.Code, http.StatusNoContent)
	}
}
