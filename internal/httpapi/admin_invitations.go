package httpapi

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/store"
)

const invitationTokenTTL = 7 * 24 * time.Hour

type invitationRequest struct {
	Email       string `json:"email"`
	Username    string `json:"username"`
	DisplayName string `json:"display_name,omitempty"`
}

func (h *adminHandler) createInvitation(w http.ResponseWriter, r *http.Request) {
	var request invitationRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	request.Email = strings.TrimSpace(request.Email)
	if request.Username == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "username is required")
		return
	}
	parsedEmail, err := mail.ParseAddress(request.Email)
	if err != nil || parsedEmail.Address != request.Email {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "email must be a valid address")
		return
	}
	plaintextToken, tokenHash, err := newInvitationToken()
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	expiresAt := time.Now().UTC().Add(invitationTokenTTL)
	payload, err := json.Marshal(map[string]string{"email": request.Email})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}

	var created store.User
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		var exists bool
		if err := tx.QueryRow(ctx, `
			SELECT EXISTS(
				SELECT 1 FROM users
				WHERE username = $1 OR email = $2
			)`, request.Username, request.Email).Scan(&exists); err != nil {
			return err
		}
		if exists {
			return unprocessableError("username or email already exists")
		}
		created, err = store.CreateUser(ctx, tx, store.User{
			Username:    request.Username,
			Email:       &request.Email,
			DisplayName: request.DisplayName,
			Status:      "invited",
		})
		if err != nil {
			return err
		}
		if _, err := store.CreateVerificationToken(ctx, tx, store.VerificationToken{
			UserID:    created.ID,
			Kind:      "invite",
			TokenHash: tokenHash,
			Payload:   payload,
			ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		if _, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "invitation.created", created.ID, nil, map[string]string{
			"email":    request.Email,
			"username": request.Username,
		})); err != nil {
			return err
		}
		return appendNotifyEvent(ctx, tx, "user.invited", map[string]string{
			"user_id": created.ID,
			"email":   request.Email,
			"token":   plaintextToken,
		})
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Request", "username or email already exists")
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, map[string]string{"id": created.ID, "status": created.Status})
}

func (h *adminHandler) resendInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userID")
	var user store.User
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		var err error
		user, err = store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if user.Status != "invited" {
			return unprocessableError("account is not invited")
		}
		plaintextToken, tokenHash, err := newInvitationToken()
		if err != nil {
			return err
		}
		expiresAt := time.Now().UTC().Add(invitationTokenTTL)
		email := ""
		if user.Email != nil {
			email = *user.Email
		}
		payload, err := json.Marshal(map[string]string{"email": email})
		if err != nil {
			return err
		}
		if _, err := tx.Exec(ctx, `
			UPDATE verification_tokens
			SET used_at = now()
			WHERE user_id = $1 AND kind = 'invite' AND used_at IS NULL`, id); err != nil {
			return err
		}
		if _, err := store.CreateVerificationToken(ctx, tx, store.VerificationToken{
			UserID:    id,
			Kind:      "invite",
			TokenHash: tokenHash,
			Payload:   payload,
			ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		if _, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "invitation.resent", id, nil, map[string]string{
			"email": email,
		})); err != nil {
			return err
		}
		return appendNotifyEvent(ctx, tx, "user.invited", map[string]string{
			"user_id": id,
			"email":   email,
			"token":   plaintextToken,
		})
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) cancelInvitation(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "userID")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if before.Status != "invited" {
			return unprocessableError("account is not invited")
		}
		if err := store.DeleteUser(ctx, tx, id); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "invitation.cancelled", id, before, nil))
		return err
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func newInvitationToken() (string, string, error) {
	data := make([]byte, 32)
	if _, err := rand.Read(data); err != nil {
		return "", "", err
	}
	plaintext := base64.RawURLEncoding.EncodeToString(data)
	sum := sha256.Sum256([]byte(plaintext))
	return plaintext, hex.EncodeToString(sum[:]), nil
}
