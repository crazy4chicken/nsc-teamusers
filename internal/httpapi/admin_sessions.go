package httpapi

import (
	"context"
	"errors"
	"net/http"

	"github.com/go-chi/chi/v5"

	"teamusers/internal/store"
)

func (h *adminHandler) listUserSessions(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	if _, err := store.GetUser(r.Context(), h.q, userID); err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	sessions, err := store.ListSessionsByUser(r.Context(), h.q, userID)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	if _, err := h.audit.Append(r.Context(), h.q, h.auditEntry(r, nil, "admin.sessions.listed", userID, nil, nil)); err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, sessionResponses(sessions))
}

func (h *adminHandler) deleteUserSession(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	sessionID := chi.URLParam(r, "sid")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		if _, err := store.GetUser(ctx, tx, userID); err != nil {
			return err
		}
		rows, err := store.DeleteSessionForUser(ctx, tx, sessionID, userID)
		if err != nil {
			return err
		}
		if rows == 0 {
			return store.ErrNotFound
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "admin.session.revoked", sessionID,
			map[string]string{"user_id": userID, "session_id": sessionID}, nil))
		return err
	})
	if errors.Is(err, store.ErrNotFound) {
		WriteProblem(w, r, http.StatusNotFound, "Not Found", "the requested resource was not found")
		return
	}
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
func (h *adminHandler) deleteAllUserSessions(w http.ResponseWriter, r *http.Request) {
	userID := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		if _, err := store.GetUser(ctx, tx, userID); err != nil {
			return err
		}
		if err := store.DeleteAllSessionsForUser(ctx, tx, userID); err != nil {
			return err
		}
		_, aerr := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "admin.sessions.revoked", userID, nil, nil))
		return aerr
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func sessionResponses(sessions []store.Session) []SessionResponse {
	responses := make([]SessionResponse, 0, len(sessions))
	for _, session := range sessions {
		responses = append(responses, SessionResponse{
			ID:        session.ID,
			CreatedAt: session.CreatedAt,
			ExpiresAt: session.ExpiresAt,
		})
	}
	return responses
}
