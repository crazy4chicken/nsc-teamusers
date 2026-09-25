package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/config"
	"teamusers/internal/httpapi"
	"teamusers/internal/store"
)

type meProfileResponse struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Email           *string    `json:"email,omitempty"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
}

type passwordChangeRequest struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (s *Service) profile(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	user, err := store.GetUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, profileResponse(user))
}

func (s *Service) patchProfile(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var fields map[string]json.RawMessage
	if !decodeJSON(w, r, &fields) {
		return
	}
	if fields == nil {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "display_name is required")
		return
	}
	var displayName string
	for field, raw := range fields {
		switch field {
		case "display_name":
			if err := json.Unmarshal(raw, &displayName); err != nil {
				httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "display_name must be a string")
				return
			}
		case "email":
			httpapi.WriteProblem(w, r, http.StatusUnprocessableEntity, "Unsupported Field", "email change is not supported")
			return
		default:
			httpapi.WriteProblem(w, r, http.StatusUnprocessableEntity, "Unsupported Field", "unsupported field: "+field)
			return
		}
	}
	if _, ok := fields["display_name"]; !ok {
		httpapi.WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "display_name is required")
		return
	}

	var updated store.User
	err := store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetUser(ctx, tx, subject.UserID)
		if err != nil {
			return err
		}
		candidate := before
		candidate.DisplayName = displayName
		updated, err = store.UpdateUser(ctx, tx, candidate)
		if err != nil {
			return err
		}
		return s.appendSelfAudit(ctx, tx, "user.updated", subject.UserID, subject.UserID, profileResponse(before), profileResponse(updated))
	})
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, profileResponse(updated))
}

func (s *Service) changePassword(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var request passwordChangeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.CurrentPassword == "" {
		writeAuthProblem(w, r, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	credential, err := store.GetCredential(r.Context(), s.q, subject.UserID, "password")
	if errors.Is(err, pgx.ErrNoRows) {
		writeAuthProblem(w, r, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	valid, acquired := s.verifyPassword(r.Context(), credential.Hash, request.CurrentPassword)
	if !acquired {
		writeRateLimited(w, r)
		return
	}
	if !valid {
		writeAuthProblem(w, r, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	if !config.ValidatePassword(request.NewPassword, s.cfg.PasswordMinLength) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "weak_password")
		return
	}
	newHash, err := HashPassword(request.NewPassword)
	if err != nil {
		writeInternal(w, r)
		return
	}
	rotatedAt := s.now()
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		credential.Hash = newHash
		credential.RotatedAt = &rotatedAt
		if _, err := store.UpdateCredential(ctx, tx, credential); err != nil {
			return err
		}
		if err := store.DeleteAllSessionsForUser(ctx, tx, subject.UserID); err != nil {
			return err
		}
		return s.appendSelfAudit(ctx, tx, "password.changed", subject.UserID, subject.UserID, nil, map[string]any{
			"sessions_revoked": true,
		})
	})
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"message":          "password changed; all sessions were revoked; sign in again",
		"sessions_revoked": true,
	})
}

func (s *Service) listOwnSessions(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	sessions, err := store.ListSessionsByUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponses(sessions))
}

func (s *Service) deleteOwnSession(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	sessionID := chi.URLParam(r, "id")
	err := store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		rows, err := store.DeleteSessionForUser(ctx, tx, sessionID, subject.UserID)
		if err != nil {
			return err
		}
		if rows == 0 {
			return store.ErrNotFound
		}
		return s.appendSelfAudit(ctx, tx, "session.revoked", subject.UserID, sessionID, sessionID, nil)
	})
	if errors.Is(err, store.ErrNotFound) {
		httpapi.WriteProblem(w, r, http.StatusNotFound, "Not Found", "the requested resource was not found")
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func profileResponse(user store.User) meProfileResponse {
	return meProfileResponse{
		ID:              user.ID,
		Username:        user.Username,
		Email:           user.Email,
		DisplayName:     user.DisplayName,
		Status:          user.Status,
		EmailVerifiedAt: user.EmailVerifiedAt,
		CreatedAt:       user.CreatedAt,
	}
}

func sessionResponses(sessions []store.Session) []httpapi.SessionResponse {
	responses := make([]httpapi.SessionResponse, 0, len(sessions))
	for _, session := range sessions {
		responses = append(responses, httpapi.SessionResponse{
			ID:        session.ID,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
		})
	}
	return responses
}

func (s *Service) appendSelfAudit(ctx context.Context, q store.Q, action, actorID, target string, before, after any) error {
	if s.audit == nil {
		return nil
	}
	actor := actorID
	_, err := s.audit.Append(ctx, q, auditlog.Entry{
		ActorID: &actor,
		Action:  action,
		Target:  target,
		Before:  before,
		After:   after,
	})
	return err
}
