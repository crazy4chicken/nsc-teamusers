package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/mail"
	"sort"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/authz"
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

type emailChangeRequest struct {
	NewEmail string `json:"new_email"`
	Password string `json:"password"`
}

type emailChangeConfirmRequest struct {
	Token string `json:"token"`
}

type deleteProfileRequest struct {
	Password string `json:"password"`
}

type exportProfileResponse struct {
	Profile              exportProfile             `json:"profile"`
	Memberships          []exportMembership        `json:"memberships"`
	EffectivePermissions []string                  `json:"effective_permissions"`
	ActiveSessions       []httpapi.SessionResponse `json:"active_sessions"`
	TOTPEnabled          bool                      `json:"totp_enabled"`
	PasskeyCount         int                       `json:"passkey_count"`
}

type exportProfile struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Email           *string    `json:"email"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	EmailVerifiedAt *time.Time `json:"email_verified_at"`
	CreatedAt       time.Time  `json:"created_at"`
}

type exportMembership struct {
	GroupID string `json:"group_id"`
	TeamID  string `json:"team_id"`
}

var errEmailTaken = errors.New("email is already in use")

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

func (s *Service) changeEmail(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var request emailChangeRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.NewEmail = strings.TrimSpace(request.NewEmail)
	if request.Password == "" {
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
	valid, acquired := s.verifyPassword(r.Context(), credential.Hash, request.Password)
	if !acquired {
		writeRateLimited(w, r)
		return
	}
	if !valid {
		writeAuthProblem(w, r, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	parsedEmail, err := mail.ParseAddress(request.NewEmail)
	if err != nil || parsedEmail.Address != request.NewEmail {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "invalid_email")
		return
	}
	plaintextToken, tokenHash, err := newVerificationToken()
	if err != nil {
		writeInternal(w, r)
		return
	}
	payload, err := json.Marshal(map[string]string{"new_email": request.NewEmail})
	if err != nil {
		writeInternal(w, r)
		return
	}
	expiresAt := s.now().Add(24 * time.Hour)
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		taken, err := store.IsEmailTaken(ctx, tx, request.NewEmail, subject.UserID)
		if err != nil {
			return err
		}
		if taken {
			return errEmailTaken
		}
		if _, err := store.CreateVerificationToken(ctx, tx, store.VerificationToken{
			UserID:    subject.UserID,
			Kind:      "email_change",
			TokenHash: tokenHash,
			Payload:   payload,
			ExpiresAt: expiresAt,
		}); err != nil {
			return err
		}
		if err := appendNotifyEvent(ctx, tx, "email.change_verification", map[string]string{
			"user_id":   subject.UserID,
			"new_email": request.NewEmail,
			"token":     plaintextToken,
		}); err != nil {
			return err
		}
		return s.appendSelfAudit(ctx, tx, "email.change_requested", subject.UserID, subject.UserID, nil, nil)
	})
	if errors.Is(err, errEmailTaken) {
		writeAuthProblem(w, r, http.StatusUnprocessableEntity, "email_taken")
		return
	}
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) confirmEmailChange(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var request emailChangeConfirmRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Token = strings.TrimSpace(request.Token)
	if request.Token == "" {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	err := store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		userID, kind, payload, err := store.ConsumeVerificationTokenWithPayload(ctx, tx, hashVerificationToken(request.Token))
		if errors.Is(err, store.ErrNotFound) || (err == nil && (kind != "email_change" || userID != subject.UserID)) {
			return store.ErrNotFound
		}
		if err != nil {
			return err
		}
		var change struct {
			NewEmail string `json:"new_email"`
		}
		if err := json.Unmarshal(payload, &change); err != nil {
			return store.ErrNotFound
		}
		change.NewEmail = strings.TrimSpace(change.NewEmail)
		parsedEmail, err := mail.ParseAddress(change.NewEmail)
		if err != nil || parsedEmail.Address != change.NewEmail {
			return store.ErrNotFound
		}
		taken, err := store.IsEmailTaken(ctx, tx, change.NewEmail, subject.UserID)
		if err != nil {
			return err
		}
		if taken {
			return store.ErrNotFound
		}
		if _, err := store.UpdateUserEmail(ctx, tx, subject.UserID, change.NewEmail, s.now()); err != nil {
			return err
		}
		return s.appendSelfAudit(ctx, tx, "email.changed", subject.UserID, subject.UserID, nil, nil)
	})
	if errors.Is(err, store.ErrNotFound) {
		writeAuthProblem(w, r, http.StatusBadRequest, "invalid_token")
		return
	}
	if err != nil {
		writeInternal(w, r)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) deleteProfile(w http.ResponseWriter, r *http.Request) {
	subject, ok := httpapi.SubjectFrom(r.Context())
	if !ok || subject.UserID == "" {
		writeUnauthorized(w, r)
		return
	}
	var request deleteProfileRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Password == "" {
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
	valid, acquired := s.verifyPassword(r.Context(), credential.Hash, request.Password)
	if !acquired {
		writeRateLimited(w, r)
		return
	}
	if !valid {
		writeAuthProblem(w, r, http.StatusUnauthorized, "invalid_credentials")
		return
	}
	deletedID := store.NewID()
	deletedUsername := "deleted_" + deletedID
	deletedEmail := deletedUsername + "@deleted.invalid"
	err = store.WithAdminTx(r.Context(), s.q, func(ctx context.Context, tx store.Tx) error {
		if err := store.AnonymizeUser(ctx, tx, subject.UserID, deletedUsername, deletedEmail); err != nil {
			return err
		}
		if _, err := store.BumpUserPermVer(ctx, tx, subject.UserID); err != nil {
			return err
		}
		if err := store.DeleteAllCredentials(ctx, tx, subject.UserID); err != nil {
			return err
		}
		if err := store.DeleteAllSessionsForUser(ctx, tx, subject.UserID); err != nil {
			return err
		}
		return s.appendSelfAudit(ctx, tx, "user.erased", subject.UserID, subject.UserID, nil, nil)
	})
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Service) exportProfile(w http.ResponseWriter, r *http.Request) {
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
	memberships, err := store.ListAllMembershipsByUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	exportMemberships := make([]exportMembership, 0, len(memberships))
	for _, membership := range memberships {
		exportMemberships = append(exportMemberships, exportMembership{
			GroupID: membership.GroupID,
			TeamID:  membership.TeamID,
		})
	}

	permissionSet, err := authz.Resolve(r.Context(), s.q, subject.UserID)
	if err != nil && !errors.Is(err, authz.ErrUserDisabled) {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	effectivePermissions := make([]string, 0)
	if permissionSet != nil {
		seen := make(map[string]struct{}, len(permissionSet.Grants))
		for _, grant := range permissionSet.Grants {
			key := grant.Permission.String()
			if _, found := seen[key]; found {
				continue
			}
			seen[key] = struct{}{}
			effectivePermissions = append(effectivePermissions, key)
		}
	}
	sort.Strings(effectivePermissions)
	sessions, err := store.ListSessionsByUser(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	activeSessions := sessionResponses(sessions)
	totpEnabled := false
	if _, err := store.GetCredential(r.Context(), s.q, subject.UserID, "totp"); err == nil {
		totpEnabled = true
	} else if !errors.Is(err, pgx.ErrNoRows) {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	passkeys, err := store.GetPasskeys(r.Context(), s.q, subject.UserID)
	if err != nil {
		httpapi.WriteStoreProblem(w, r, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="user-export.json"`)
	writeJSON(w, http.StatusOK, exportProfileResponse{
		Profile: exportProfile{
			ID:              user.ID,
			Username:        user.Username,
			Email:           user.Email,
			DisplayName:     user.DisplayName,
			Status:          user.Status,
			EmailVerifiedAt: user.EmailVerifiedAt,
			CreatedAt:       user.CreatedAt,
		},
		Memberships:          exportMemberships,
		EffectivePermissions: effectivePermissions,
		ActiveSessions:       activeSessions,
		TOTPEnabled:          totpEnabled,
		PasskeyCount:         len(passkeys),
	})
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
