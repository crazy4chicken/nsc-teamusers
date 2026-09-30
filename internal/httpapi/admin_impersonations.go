package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

const (
	defaultImpersonationTTLSeconds int64 = 300
	maxImpersonationTTLSeconds     int64 = 900
)

type impersonationRequest struct {
	UserID     string `json:"user_id"`
	Reason     string `json:"reason"`
	TTLSeconds *int64 `json:"ttl_seconds,omitempty"`
}

type impersonationResponse struct {
	AccessToken string    `json:"access_token"`
	TokenType   string    `json:"token_type"`
	ExpiresAt   time.Time `json:"expires_at"`
}

type impersonationTokenMinter interface {
	MintImpersonationToken(context.Context, store.User, string, time.Duration) (string, time.Time, string, bool, error)
}

func (h *adminHandler) createImpersonation(w http.ResponseWriter, r *http.Request) {
	var request impersonationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.UserID = strings.TrimSpace(request.UserID)
	request.Reason = strings.TrimSpace(request.Reason)
	if request.UserID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "user_id is required")
		return
	}
	if utf8.RuneCountInString(request.Reason) < 3 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "reason must be at least 3 characters")
		return
	}

	ttlSeconds := defaultImpersonationTTLSeconds
	if request.TTLSeconds != nil {
		ttlSeconds = *request.TTLSeconds
	}
	if ttlSeconds < 1 || ttlSeconds > maxImpersonationTTLSeconds {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "ttl_seconds must be between 1 and 900")
		return
	}

	subject, ok := SubjectFrom(r.Context())
	if !ok {
		WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "an authenticated subject is required")
		return
	}
	if subject.Kind != "user" {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "administrative access requires a user subject")
		return
	}

	target, err := store.GetUser(r.Context(), h.q, request.UserID)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	if target.Status != "active" {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "the target user must be active")
		return
	}
	if target.ID == subject.UserID {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "self-impersonation is not allowed")
		return
	}
	if _, err := store.GetCredential(r.Context(), h.q, target.ID, "service"); err == nil {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "service accounts cannot be impersonated")
		return
	} else if !errors.Is(err, pgx.ErrNoRows) {
		WriteStoreProblem(w, r, err)
		return
	}

	minter, ok := h.keyRotator.(impersonationTokenMinter)
	if !ok {
		WriteProblem(w, r, http.StatusInternalServerError, "Internal Server Error", "impersonation token issuance is unavailable")
		return
	}
	accessToken, expiresAt, jti, denied, err := minter.MintImpersonationToken(r.Context(), target, subject.UserID, time.Duration(ttlSeconds)*time.Second)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	if denied {
		WriteProblem(w, r, http.StatusForbidden, "Forbidden", "the target user is not eligible for impersonation")
		return
	}

	after := map[string]any{
		"actor":       subject.UserID,
		"target":      target.ID,
		"reason":      request.Reason,
		"ttl_seconds": ttlSeconds,
		"jti":         jti,
		"expires_at":  expiresAt,
	}
	if _, err := h.audit.Append(r.Context(), h.q, h.auditEntry(r, nil, "impersonation.started", target.ID, nil, after)); err != nil {
		WriteStoreProblem(w, r, err)
		return
	}

	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("Pragma", "no-cache")
	writeJSON(w, http.StatusOK, impersonationResponse{
		AccessToken: accessToken,
		TokenType:   "Bearer",
		ExpiresAt:   expiresAt,
	})
}
