package httpapi

import (
	"context"
	"encoding/csv"
	"errors"
	"io"
	"mime"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/config"
	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

const maxBatchItems = 500

type userBatchRequest struct {
	IDs []string `json:"ids,omitempty"`
	Op  string   `json:"op"`
}

type groupMembersBatchRequest struct {
	UserIDs []string `json:"user_ids,omitempty"`
}

type batchResult struct {
	ID    string `json:"id"`
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type importResult struct {
	Row      int    `json:"row"`
	Username string `json:"username"`
	OK       bool   `json:"ok"`
	Error    string `json:"error,omitempty"`
	ID       string `json:"id,omitempty"`
}

type importRecord struct {
	Username    string
	Email       *string
	DisplayName string
	Password    string
}

var errAlreadyMember = errors.New("already_member")

func (h *adminHandler) batchUserStatus(w http.ResponseWriter, r *http.Request) {
	var request userBatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Op = strings.ToLower(strings.TrimSpace(request.Op))
	if request.Op != "disable" && request.Op != "enable" {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Operation", "op must be disable or enable")
		return
	}
	if len(request.IDs) > maxBatchItems {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Too Many Items", "a maximum of 500 ids is allowed")
		return
	}

	status := "disabled"
	action := "user.disabled"
	if request.Op == "enable" {
		status = "active"
		action = "user.enabled"
	}
	results := make([]batchResult, 0, len(request.IDs))
	for _, rawID := range request.IDs {
		id := strings.TrimSpace(rawID)
		result := batchResult{ID: id}
		if id == "" {
			result.Error = "invalid_id"
			results = append(results, result)
			continue
		}
		err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
			_, err := h.applyUserStatus(ctx, tx, r, id, status, action)
			return err
		})
		if err != nil {
			result.Error = batchRowError(err)
		} else {
			result.OK = true
		}
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

// applyUserStatus is shared by the single-user disable endpoint and batch
// status operations so lockout, permission, session, notification, and audit
// transitions stay identical.
func (h *adminHandler) applyUserStatus(ctx context.Context, tx store.Tx, r *http.Request, id, status, action string) (store.User, error) {
	before, err := store.GetUser(ctx, tx, id)
	if err != nil {
		return store.User{}, err
	}
	candidate := before
	candidate.Status = status
	updated, err := store.UpdateUser(ctx, tx, candidate)
	if err != nil {
		return store.User{}, err
	}
	if status == "disabled" {
		if err := store.ResetFailedLogins(ctx, tx, id); err != nil {
			return store.User{}, err
		}
		updated.FailedLogins = 0
		updated.LockedUntil = nil
		version, err := store.BumpUserPermVer(ctx, tx, id)
		if err != nil {
			return store.User{}, err
		}
		updated.PermVer = version
		if err := store.RevokeAllUserSessions(ctx, tx, id, "user disabled"); err != nil {
			return store.User{}, err
		}
		if err := appendUserDisabledEvents(ctx, tx, id, nil); err != nil {
			return store.User{}, err
		}
	} else if before.Status != status {
		version, err := store.BumpUserPermVer(ctx, tx, id)
		if err != nil {
			return store.User{}, err
		}
		updated.PermVer = version
		if err := appendPermissionChange(ctx, tx, []string{id}, nil); err != nil {
			return store.User{}, err
		}
	}
	if _, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, action, id, before, updated)); err != nil {
		return store.User{}, err
	}
	return updated, nil
}

func (h *adminHandler) batchGroupMembers(w http.ResponseWriter, r *http.Request) {
	groupID := strings.TrimSpace(chi.URLParam(r, "id"))
	var request groupMembersBatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.UserIDs) > maxBatchItems {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Too Many Items", "a maximum of 500 user_ids is allowed")
		return
	}

	var group store.Group
	if err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		var err error
		group, err = store.GetGroup(ctx, tx, groupID)
		return err
	}); err != nil {
		WriteStoreProblem(w, r, err)
		return
	}

	results := make([]batchResult, 0, len(request.UserIDs))
	for _, rawUserID := range request.UserIDs {
		userID := strings.TrimSpace(rawUserID)
		result := batchResult{ID: userID}
		if userID == "" {
			result.Error = "invalid_id"
			results = append(results, result)
			continue
		}
		err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
			if _, err := store.GetUser(ctx, tx, userID); err != nil {
				return err
			}
			_, err := store.GetMembership(ctx, tx, groupID, userID)
			if err == nil {
				return errAlreadyMember
			}
			if !errors.Is(err, pgx.ErrNoRows) {
				return err
			}
			membership := store.Membership{TeamID: group.TeamID, GroupID: groupID, UserID: userID}
			if err := store.PutMembership(ctx, tx, membership); err != nil {
				return err
			}
			if err := bumpUserPermVers(ctx, tx, []string{userID}); err != nil {
				return err
			}
			teamID := group.TeamID
			if err := appendPermissionChange(ctx, tx, []string{userID}, &teamID); err != nil {
				return err
			}
			_, err = h.audit.Append(ctx, tx, h.auditEntry(r, &teamID, "membership.created", groupID+"/"+userID, nil, membership))
			return err
		})
		if err != nil {
			result.Error = batchRowError(err)
		} else {
			result.OK = true
		}
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func (h *adminHandler) importUsers(w http.ResponseWriter, r *http.Request) {
	mediaType, _, err := mime.ParseMediaType(strings.TrimSpace(r.Header.Get("Content-Type")))
	if err != nil || !strings.EqualFold(mediaType, "text/csv") {
		WriteProblem(w, r, http.StatusUnsupportedMediaType, "Unsupported Media Type", "Content-Type must be text/csv")
		return
	}

	records, err := parseImportCSV(r)
	if err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid CSV", err.Error())
		return
	}
	results := make([]importResult, 0, len(records))
	seen := make(map[string]struct{}, len(records))
	for index, record := range records {
		result := importResult{Row: index + 2, Username: record.Username}
		username := strings.TrimSpace(record.Username)
		result.Username = username
		if username == "" {
			result.Error = "username_required"
			results = append(results, result)
			continue
		}
		if !config.ValidatePassword(record.Password, h.cfg.PasswordMinLength) {
			result.Error = "weak_password"
			results = append(results, result)
			continue
		}
		key := strings.ToLower(username)
		if _, ok := seen[key]; ok {
			result.Error = "duplicate_username"
			results = append(results, result)
			continue
		}
		seen[key] = struct{}{}

		hash, err := passwd.Hash(record.Password)
		if err != nil {
			result.Error = "operation_failed"
			results = append(results, result)
			continue
		}
		var created store.User
		err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
			user, err := store.CreateUser(ctx, tx, store.User{
				Username:    username,
				Email:       record.Email,
				DisplayName: record.DisplayName,
				Status:      "active",
			})
			if err != nil {
				return err
			}
			created = user
			if _, err := store.CreateCredential(ctx, tx, store.Credential{
				UserID:     user.ID,
				Kind:       "password",
				Hash:       hash,
				MustChange: true,
			}); err != nil {
				return err
			}
			if _, err := h.audit.Append(ctx, tx, h.auditEntry(r, nil, "user.created", user.ID, nil, user)); err != nil {
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
			result.Error = importRowError(err)
		} else {
			result.OK = true
			result.ID = created.ID
		}
		results = append(results, result)
	}
	writeJSON(w, http.StatusOK, map[string]any{"results": results})
}

func parseImportCSV(r *http.Request) ([]importRecord, error) {
	reader := csv.NewReader(r.Body)
	header, err := reader.Read()
	if err != nil {
		if errors.Is(err, io.EOF) {
			return nil, errors.New("CSV must include the header row")
		}
		return nil, errors.New("malformed CSV")
	}
	if len(header) != 4 {
		return nil, errors.New("CSV header must be username,email,display_name,password")
	}
	header[0] = strings.TrimPrefix(header[0], "\ufeff")
	if header[0] != "username" || header[1] != "email" || header[2] != "display_name" || header[3] != "password" {
		return nil, errors.New("CSV header must be username,email,display_name,password")
	}
	reader.FieldsPerRecord = 4
	records := make([]importRecord, 0)
	for {
		fields, err := reader.Read()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, errors.New("malformed CSV")
		}
		if len(records) == maxBatchItems {
			return nil, errors.New("a maximum of 500 rows is allowed")
		}
		email := strings.TrimSpace(fields[1])
		var emailPtr *string
		if email != "" {
			emailPtr = &email
		}
		records = append(records, importRecord{
			Username:    fields[0],
			Email:       emailPtr,
			DisplayName: fields[2],
			Password:    fields[3],
		})
	}
	return records, nil
}

func batchRowError(err error) string {
	switch {
	case errors.Is(err, errAlreadyMember):
		return "already_member"
	case errors.Is(err, pgx.ErrNoRows), errors.Is(err, store.ErrNotFound):
		return "not_found"
	default:
		return "operation_failed"
	}
}

func importRowError(err error) string {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) && pgErr.Code == "23505" {
		return "duplicate_username"
	}
	return "operation_failed"
}
