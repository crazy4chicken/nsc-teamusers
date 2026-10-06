package httpapi

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

type mfaPolicyCreateRequest struct {
	Name           string `json:"name,omitempty"`
	Priority       int    `json:"priority,omitempty"`
	SubjectKind    string `json:"subject_kind"`
	SubjectID      string `json:"subject_id,omitempty"`
	Required       *bool  `json:"required"`
	DenyUnenrolled bool   `json:"deny_unenrolled,omitempty"`
}

type mfaPolicyPatchRequest struct {
	Name           *string `json:"name,omitempty"`
	Priority       *int    `json:"priority,omitempty"`
	SubjectKind    *string `json:"subject_kind,omitempty"`
	SubjectID      *string `json:"subject_id,omitempty"`
	Required       *bool   `json:"required,omitempty"`
	DenyUnenrolled *bool   `json:"deny_unenrolled,omitempty"`
}

func (h *adminHandler) listMFAPolicies(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := ParsePage(w, r)
	if !ok {
		return
	}
	policies, next, err := store.ListMFAPolicies(r.Context(), h.q, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	WriteItems(w, policies, next)
}

func (h *adminHandler) getMFAPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := store.GetMFAPolicy(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *adminHandler) createMFAPolicy(w http.ResponseWriter, r *http.Request) {
	var request mfaPolicyCreateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Required == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "required must be a boolean")
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.SubjectKind = strings.TrimSpace(request.SubjectKind)
	request.SubjectID = strings.TrimSpace(request.SubjectID)
	if err := validateMFAPolicyFields(request.SubjectKind, request.SubjectID, request.Priority); err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}

	var created store.MFAPolicy
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		if err := validateMFAPolicySubject(ctx, tx, request.SubjectKind, request.SubjectID); err != nil {
			return err
		}
		policy, err := store.CreateMFAPolicy(ctx, tx, store.MFAPolicy{
			Name:           request.Name,
			Priority:       request.Priority,
			SubjectKind:    request.SubjectKind,
			SubjectID:      request.SubjectID,
			Required:       *request.Required,
			DenyUnenrolled: request.DenyUnenrolled,
		})
		created = policy
		if err != nil {
			return err
		}
		teamID, err := mfaPolicyAuditTeamID(ctx, tx, created.SubjectKind, created.SubjectID)
		if err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "mfa_policy.created", created.ID, nil, created))
		return err
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, created)
}

func (h *adminHandler) patchMFAPolicy(w http.ResponseWriter, r *http.Request) {
	request, presence, err := decodeMFAPolicyPatch(r)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}
	if !mfaPolicyPatchHasFields(presence) {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "at least one MFA policy field is required")
		return
	}
	if presence["name"] && request.Name == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "name must be a string")
		return
	}
	if presence["priority"] && request.Priority == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "priority must be an integer")
		return
	}
	if presence["subject_kind"] && request.SubjectKind == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "subject_kind must be a string")
		return
	}
	if presence["subject_id"] && request.SubjectID == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "subject_id must be a string")
		return
	}
	if presence["required"] && request.Required == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "required must be a boolean")
		return
	}
	if presence["deny_unenrolled"] && request.DenyUnenrolled == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "deny_unenrolled must be a boolean")
		return
	}
	if request.Name != nil {
		value := strings.TrimSpace(*request.Name)
		request.Name = &value
	}
	if request.SubjectKind != nil {
		value := strings.TrimSpace(*request.SubjectKind)
		request.SubjectKind = &value
	}
	if request.SubjectID != nil {
		value := strings.TrimSpace(*request.SubjectID)
		request.SubjectID = &value
	}

	id := chi.URLParam(r, "id")
	var updated store.MFAPolicy
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetMFAPolicyForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		original := before
		if request.Name != nil {
			before.Name = *request.Name
		}
		if request.Priority != nil {
			before.Priority = *request.Priority
		}
		if request.SubjectKind != nil {
			before.SubjectKind = *request.SubjectKind
		}
		if request.SubjectID != nil {
			before.SubjectID = *request.SubjectID
		}
		if request.Required != nil {
			before.Required = *request.Required
		}
		if request.DenyUnenrolled != nil {
			before.DenyUnenrolled = *request.DenyUnenrolled
		}
		if err := validateMFAPolicyFields(before.SubjectKind, before.SubjectID, before.Priority); err != nil {
			return err
		}
		subjectChanged := before.SubjectKind != original.SubjectKind || before.SubjectID != original.SubjectID
		if subjectChanged {
			if err := validateMFAPolicySubject(ctx, tx, before.SubjectKind, before.SubjectID); err != nil {
				return err
			}
		}
		updated, err = store.UpdateMFAPolicy(ctx, tx, before)
		if err != nil {
			return err
		}
		teamID, err := mfaPolicyAuditTeamID(ctx, tx, updated.SubjectKind, updated.SubjectID)
		if err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "mfa_policy.updated", id, original, updated))
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

func (h *adminHandler) deleteMFAPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		policy, err := store.GetMFAPolicyForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		teamID, err := mfaPolicyAuditTeamID(ctx, tx, policy.SubjectKind, policy.SubjectID)
		if err != nil {
			return err
		}
		if err := store.DeleteMFAPolicy(ctx, tx, id); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "mfa_policy.deleted", id, policy, nil))
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

func validateMFAPolicyFields(subjectKind, subjectID string, priority int) error {
	switch subjectKind {
	case "default":
		if subjectID != "" {
			return unprocessableError("default policies must not have a subject_id")
		}
	case "team", "group", "role":
		if subjectID == "" {
			return unprocessableError("subject_id is required")
		}
	default:
		return unprocessableError("subject_kind must be one of default, team, group, role")
	}
	if priority < math.MinInt32 || priority > math.MaxInt32 {
		return unprocessableError("priority must be between -2147483648 and 2147483647")
	}
	return nil
}

func validateMFAPolicySubject(ctx context.Context, q store.Q, subjectKind, subjectID string) error {
	var err error
	switch subjectKind {
	case "default":
		return nil
	case "team":
		_, err = store.GetTeam(ctx, q, subjectID)
	case "group":
		_, err = store.GetGroup(ctx, q, subjectID)
	case "role":
		_, err = store.GetRole(ctx, q, subjectID)
	default:
		return unprocessableError("subject_kind must be one of default, team, group, role")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return unprocessableError("subject does not exist")
	}
	return err
}

func mfaPolicyAuditTeamID(ctx context.Context, q store.Q, subjectKind, subjectID string) (*string, error) {
	switch subjectKind {
	case "default":
		return nil, nil
	case "team":
		_, err := store.GetTeam(ctx, q, subjectID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &subjectID, nil
	case "group":
		group, err := store.GetGroup(ctx, q, subjectID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return &group.TeamID, nil
	case "role":
		role, err := store.GetRole(ctx, q, subjectID)
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, nil
		}
		if err != nil {
			return nil, err
		}
		return role.TeamID, nil
	default:
		return nil, unprocessableError("subject_kind must be one of default, team, group, role")
	}
}

func decodeMFAPolicyPatch(r *http.Request) (mfaPolicyPatchRequest, map[string]bool, error) {
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	data, err := io.ReadAll(body)
	if err != nil {
		return mfaPolicyPatchRequest{}, nil, errors.New("request body must be readable")
	}
	r.Body = io.NopCloser(bytes.NewReader(data))
	if len(bytes.TrimSpace(data)) == 0 {
		return mfaPolicyPatchRequest{}, nil, errors.New("request body must be a JSON object")
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil || values == nil {
		return mfaPolicyPatchRequest{}, nil, errors.New("request body must be a JSON object")
	}
	var request mfaPolicyPatchRequest
	if err := json.Unmarshal(data, &request); err != nil {
		return mfaPolicyPatchRequest{}, nil, errors.New("request body must be a valid MFA policy object")
	}
	presence := make(map[string]bool, len(values))
	for name := range values {
		presence[name] = true
	}
	return request, presence, nil
}

func mfaPolicyPatchHasFields(presence map[string]bool) bool {
	for _, name := range []string{"name", "priority", "subject_kind", "subject_id", "required", "deny_unenrolled"} {
		if presence[name] {
			return true
		}
	}
	return false
}
