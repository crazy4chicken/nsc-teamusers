package httpapi

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/config"
	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

type createUserRequest struct {
	Username        string  `json:"username"`
	Email           *string `json:"email,omitempty"`
	DisplayName     string  `json:"display_name,omitempty"`
	Password        string  `json:"password,omitempty"`
	InitialPassword string  `json:"initial_password,omitempty"`
}

type patchUserRequest struct {
	Username    *string `json:"username,omitempty"`
	Email       *string `json:"email,omitempty"`
	DisplayName *string `json:"display_name,omitempty"`
	Status      *string `json:"status,omitempty"`
}

func (h *adminHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := parsePage(w, r)
	if !ok {
		return
	}
	users, next, err := store.ListUsers(r.Context(), h.q, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeItems(w, users, next)
}

func (h *adminHandler) getUser(w http.ResponseWriter, r *http.Request) {
	user, err := store.GetUser(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, user)
}

func (h *adminHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var request createUserRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Username = strings.TrimSpace(request.Username)
	if request.Username == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "username is required")
		return
	}
	password := request.Password
	if password == "" {
		password = request.InitialPassword
	}
	if password != "" && !config.ValidatePassword(password, h.cfg.PasswordMinLength) {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "weak_password", "weak_password")
		return
	}
	var created store.User
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		user, err := store.CreateUser(ctx, tx, store.User{
			Username:    request.Username,
			Email:       request.Email,
			DisplayName: request.DisplayName,
			Status:      "active",
		})
		if err != nil {
			return err
		}
		created = user
		if password != "" {
			hash, err := passwd.Hash(password)
			if err != nil {
				return err
			}
			if _, err := store.CreateCredential(ctx, tx, store.Credential{
				UserID:     user.ID,
				Kind:       "password",
				Hash:       hash,
				MustChange: true,
			}); err != nil {
				return err
			}
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "user.created", user.ID, nil, user))
		if err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, []string{user.ID}, nil); err != nil {
			return err
		}
		return appendNotifyEvent(ctx, tx, "user.created", map[string]string{
			"user_id": user.ID, "username": user.Username,
		})
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, created)
}

func (h *adminHandler) patchUser(w http.ResponseWriter, r *http.Request) {
	var request patchUserRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Username == nil && request.Email == nil && request.DisplayName == nil && request.Status == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "at least one user field is required")
		return
	}
	id := chi.URLParam(r, "id")
	var updated store.User
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		original := before
		if request.Username != nil {
			before.Username = strings.TrimSpace(*request.Username)
			if before.Username == "" {
				return validationError("username is required")
			}
		}
		if request.Email != nil {
			before.Email = request.Email
		}
		if request.DisplayName != nil {
			before.DisplayName = *request.DisplayName
		}
		if request.Status != nil {
			status := strings.TrimSpace(*request.Status)
			if status != "active" && status != "disabled" {
				return validationError("status must be active or disabled")
			}
			before.Status = status
		}
		updated, err = store.UpdateUser(ctx, tx, before)
		if err != nil {
			return err
		}
		if original.Status != updated.Status {
			version, err := store.BumpUserPermVer(ctx, tx, id)
			if err != nil {
				return err
			}
			updated.PermVer = version
			if updated.Status == "disabled" {
				if err := store.RevokeAllUserSessions(ctx, tx, id, "user disabled"); err != nil {
					return err
				}
				if err := appendUserDisabledEvents(ctx, tx, id, nil); err != nil {
					return err
				}
				if err := store.ResetFailedLogins(ctx, tx, id); err != nil {
					return err
				}
				updated.FailedLogins = 0
				updated.LockedUntil = nil
			} else if err := appendPermissionChange(ctx, tx, []string{id}, nil); err != nil {
				return err
			}
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "user.updated", id, original, updated))
		return err
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *adminHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := store.DeleteUser(ctx, tx, id); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "user.deleted", id, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) deleteUserTOTP(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		if _, err := store.GetUser(ctx, tx, id); err != nil {
			return err
		}
		if err := store.DeleteTOTPCredentials(ctx, tx, id); err != nil {
			return err
		}
		_, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "admin.totp_reset", id, nil, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) disableUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var updated store.User
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		var err error
		updated, err = h.applyUserStatus(ctx, tx, r, id, "disabled", "user.disabled")
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *adminHandler) approveUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var updated store.User
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		if h.registrationMode() == "approval" && before.EmailVerifiedAt == nil {
			return unprocessableError("email_not_verified")
		}
		subject, ok := SubjectFrom(r.Context())
		if !ok || subject.UserID == "" {
			return validationError("approver identity is required")
		}
		updated, err = store.ApproveUser(ctx, tx, id, subject.UserID, time.Now().UTC())
		if errors.Is(err, store.ErrNotFound) {
			return unprocessableError("email_not_verified")
		}
		if err != nil {
			return err
		}
		if _, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "user.approved", id, before, updated)); err != nil {
			return err
		}
		return appendNotifyEvent(ctx, tx, "user.approved", map[string]string{"user_id": id})
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, updated)
}

func (h *adminHandler) registrationMode() string {
	switch mode := strings.ToLower(strings.TrimSpace(h.cfg.RegistrationMode)); mode {
	case "approval", "open":
		return mode
	default:
		return "closed"
	}
}

type createCredentialRequest struct {
	Kind     string `json:"kind"`
	Password string `json:"password,omitempty"`
}

// createUserCredential issues or rotates a user credential. For kind=service
// the server generates the secret and returns it exactly once; only its
// Argon2id hash is stored. Credential material never enters audit or logs.
func (h *adminHandler) createUserCredential(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	var request createCredentialRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	var secret string
	switch request.Kind {
	case "password":
		if request.Password == "" {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "password is required for kind=password")
			return
		}
	case "service":
		random := make([]byte, 32)
		if _, err := rand.Read(random); err != nil {
			WriteStoreProblem(w, r, err)
			return
		}
		secret = base64.RawURLEncoding.EncodeToString(random)
	default:
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "kind must be password or service")
		return
	}
	plaintext := request.Password
	if request.Kind == "password" && !config.ValidatePassword(plaintext, h.cfg.PasswordMinLength) {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "weak_password", "weak_password")
		return
	}
	if request.Kind == "service" {
		plaintext = secret
	}
	hash, err := passwd.Hash(plaintext)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	var user store.User
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		loaded, err := store.GetUser(ctx, tx, id)
		if err != nil {
			return err
		}
		user = loaded
		credential := store.Credential{UserID: id, Kind: request.Kind, Hash: hash, MustChange: request.Kind == "password"}
		if _, err := store.UpdateCredential(ctx, tx, credential); err != nil {
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			if _, err := store.CreateCredential(ctx, tx, credential); err != nil {
				return err
			}
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "credential.rotated", id, nil, map[string]string{"kind": request.Kind}))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	response := map[string]string{"user_id": user.ID, "username": user.Username, "kind": request.Kind}
	if request.Kind == "service" {
		response["client_id"] = user.Username
		response["client_secret"] = secret
	}
	writeCreated(w, response)
}
