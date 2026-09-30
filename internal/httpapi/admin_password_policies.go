package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"net/http"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

type passwordPolicyCreateRequest struct {
	Name          string `json:"name,omitempty"`
	Priority      int    `json:"priority,omitempty"`
	SubjectKind   string `json:"subject_kind"`
	SubjectID     string `json:"subject_id"`
	MinLength     *int   `json:"min_length,omitempty"`
	RequireLetter *bool  `json:"require_letter,omitempty"`
	RequireUpper  *bool  `json:"require_upper,omitempty"`
	RequireLower  *bool  `json:"require_lower,omitempty"`
	RequireDigit  *bool  `json:"require_digit,omitempty"`
	RequireSymbol *bool  `json:"require_symbol,omitempty"`
	HistoryCount  *int   `json:"history_count,omitempty"`
	BreachCheck   *bool  `json:"breach_check,omitempty"`
}

type passwordPolicyPatchRequest struct {
	Name          *string `json:"name,omitempty"`
	Priority      *int    `json:"priority,omitempty"`
	SubjectKind   *string `json:"subject_kind,omitempty"`
	SubjectID     *string `json:"subject_id,omitempty"`
	MinLength     *int    `json:"min_length,omitempty"`
	RequireLetter *bool   `json:"require_letter,omitempty"`
	RequireUpper  *bool   `json:"require_upper,omitempty"`
	RequireLower  *bool   `json:"require_lower,omitempty"`
	RequireDigit  *bool   `json:"require_digit,omitempty"`
	RequireSymbol *bool   `json:"require_symbol,omitempty"`
	HistoryCount  *int    `json:"history_count,omitempty"`
	BreachCheck   *bool   `json:"breach_check,omitempty"`
}

func (h *adminHandler) listPasswordPolicies(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := parsePage(w, r)
	if !ok {
		return
	}
	policies, next, err := store.ListPasswordPolicies(r.Context(), h.q, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeItems(w, policies, next)
}

func (h *adminHandler) getPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	policy, err := store.GetPasswordPolicy(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, policy)
}

func (h *adminHandler) createPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	var request passwordPolicyCreateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Name = strings.TrimSpace(request.Name)
	request.SubjectKind = strings.TrimSpace(request.SubjectKind)
	request.SubjectID = strings.TrimSpace(request.SubjectID)
	if err := validatePasswordPolicyFields(request.SubjectKind, request.SubjectID, request.MinLength, request.HistoryCount, request.Priority); err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}

	var created store.PasswordPolicy
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		if err := validatePasswordPolicySubject(ctx, tx, request.SubjectKind, request.SubjectID); err != nil {
			return err
		}
		createdPolicy, err := store.CreatePasswordPolicy(ctx, tx, store.PasswordPolicy{
			Name:          request.Name,
			Priority:      request.Priority,
			SubjectKind:   request.SubjectKind,
			SubjectID:     request.SubjectID,
			MinLength:     request.MinLength,
			RequireLetter: request.RequireLetter,
			RequireUpper:  request.RequireUpper,
			RequireLower:  request.RequireLower,
			RequireDigit:  request.RequireDigit,
			RequireSymbol: request.RequireSymbol,
			HistoryCount:  request.HistoryCount,
			BreachCheck:   request.BreachCheck,
		})
		created = createdPolicy
		if err != nil {
			return err
		}
		teamID, err := passwordPolicyAuditTeamID(ctx, tx, created.SubjectKind, created.SubjectID)
		if err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "password_policy.created", created.ID, nil, created))
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

func (h *adminHandler) patchPasswordPolicy(w http.ResponseWriter, r *http.Request) {
	request, presence, err := decodePasswordPolicyPatch(w, r)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", err.Error())
		return
	}
	if !passwordPolicyPatchHasFields(request, presence) {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "at least one password policy field is required")
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
	var updated store.PasswordPolicy
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetPasswordPolicyForUpdate(ctx, tx, id)
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
		if presence["min_length"] {
			before.MinLength = request.MinLength
		}
		if presence["require_letter"] {
			before.RequireLetter = request.RequireLetter
		}
		if presence["require_upper"] {
			before.RequireUpper = request.RequireUpper
		}
		if presence["require_lower"] {
			before.RequireLower = request.RequireLower
		}
		if presence["require_digit"] {
			before.RequireDigit = request.RequireDigit
		}
		if presence["require_symbol"] {
			before.RequireSymbol = request.RequireSymbol
		}
		if presence["history_count"] {
			before.HistoryCount = request.HistoryCount
		}
		if presence["breach_check"] {
			before.BreachCheck = request.BreachCheck
		}
		subjectChanged := before.SubjectKind != original.SubjectKind || before.SubjectID != original.SubjectID
		if err := validatePasswordPolicyFields(before.SubjectKind, before.SubjectID, before.MinLength, before.HistoryCount, before.Priority); err != nil {
			return err
		}
		if subjectChanged {
			if err := validatePasswordPolicySubject(ctx, tx, before.SubjectKind, before.SubjectID); err != nil {
				return err
			}
		}
		updated, err = store.UpdatePasswordPolicy(ctx, tx, before)
		if err != nil {
			return err
		}
		teamID, err := passwordPolicyAuditTeamID(ctx, tx, updated.SubjectKind, updated.SubjectID)
		if err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "password_policy.updated", id, original, updated))
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

func (h *adminHandler) deletePasswordPolicy(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetPasswordPolicyForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		teamID, err := passwordPolicyAuditTeamID(ctx, tx, before.SubjectKind, before.SubjectID)
		if err != nil {
			return err
		}
		if err := store.DeletePasswordPolicy(ctx, tx, id); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "password_policy.deleted", id, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func validatePasswordPolicyFields(subjectKind, subjectID string, minLength, historyCount *int, priority int) error {
	switch subjectKind {
	case "user", "team", "group", "role":
	default:
		return unprocessableError("subject_kind must be one of user, team, group, role")
	}
	if subjectID == "" {
		return unprocessableError("subject_id is required")
	}
	if priority < math.MinInt32 || priority > math.MaxInt32 {
		return unprocessableError("priority must be between -2147483648 and 2147483647")
	}
	if minLength != nil && (*minLength < 1 || *minLength > 1024) {
		return unprocessableError("min_length must be between 1 and 1024")
	}
	if historyCount != nil && (*historyCount < 0 || *historyCount > store.PasswordHistoryLimit) {
		return unprocessableError(fmt.Sprintf("history_count must be between 0 and %d", store.PasswordHistoryLimit))
	}
	return nil
}

func validatePasswordPolicySubject(ctx context.Context, q store.Q, subjectKind, subjectID string) error {
	var err error
	switch subjectKind {
	case "user":
		_, err = store.GetUser(ctx, q, subjectID)
	case "team":
		_, err = store.GetTeam(ctx, q, subjectID)
	case "group":
		_, err = store.GetGroup(ctx, q, subjectID)
	case "role":
		_, err = store.GetRole(ctx, q, subjectID)
	default:
		return unprocessableError("subject_kind must be one of user, team, group, role")
	}
	if errors.Is(err, pgx.ErrNoRows) {
		return unprocessableError("subject does not exist")
	}
	return err
}
func passwordPolicyAuditTeamID(ctx context.Context, q store.Q, subjectKind, subjectID string) (*string, error) {
	switch subjectKind {
	case "user":
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
		return nil, unprocessableError("subject_kind must be one of user, team, group, role")
	}
}

func decodePasswordPolicyPatch(w http.ResponseWriter, r *http.Request) (passwordPolicyPatchRequest, map[string]bool, error) {
	body := r.Body
	if body == nil {
		body = http.NoBody
	}
	data, err := io.ReadAll(http.MaxBytesReader(w, body, 1<<20))
	if err != nil {
		return passwordPolicyPatchRequest{}, nil, errors.New("request body could not be read")
	}
	var values map[string]json.RawMessage
	if err := json.Unmarshal(data, &values); err != nil {
		return passwordPolicyPatchRequest{}, nil, errors.New("request body must be valid JSON")
	}
	allowed := map[string]struct{}{
		"name": {}, "priority": {}, "subject_kind": {}, "subject_id": {},
		"min_length": {}, "require_letter": {}, "require_upper": {},
		"require_lower": {}, "require_digit": {}, "require_symbol": {},
		"history_count": {}, "breach_check": {},
	}
	presence := make(map[string]bool, len(values))
	var request passwordPolicyPatchRequest
	for field, raw := range values {
		if _, ok := allowed[field]; !ok {
			return passwordPolicyPatchRequest{}, nil, fmt.Errorf("unknown field %q", field)
		}
		presence[field] = true
		var decodeErr error
		switch field {
		case "name":
			decodeErr = json.Unmarshal(raw, &request.Name)
		case "priority":
			decodeErr = json.Unmarshal(raw, &request.Priority)
		case "subject_kind":
			decodeErr = json.Unmarshal(raw, &request.SubjectKind)
		case "subject_id":
			decodeErr = json.Unmarshal(raw, &request.SubjectID)
		case "min_length":
			decodeErr = json.Unmarshal(raw, &request.MinLength)
		case "require_letter":
			decodeErr = json.Unmarshal(raw, &request.RequireLetter)
		case "require_upper":
			decodeErr = json.Unmarshal(raw, &request.RequireUpper)
		case "require_lower":
			decodeErr = json.Unmarshal(raw, &request.RequireLower)
		case "require_digit":
			decodeErr = json.Unmarshal(raw, &request.RequireDigit)
		case "require_symbol":
			decodeErr = json.Unmarshal(raw, &request.RequireSymbol)
		case "history_count":
			decodeErr = json.Unmarshal(raw, &request.HistoryCount)
		case "breach_check":
			decodeErr = json.Unmarshal(raw, &request.BreachCheck)
		}
		if decodeErr != nil {
			return passwordPolicyPatchRequest{}, nil, fmt.Errorf("%s must have a valid value", field)
		}
	}
	return request, presence, nil
}

func passwordPolicyPatchHasFields(_ passwordPolicyPatchRequest, presence map[string]bool) bool {
	for _, present := range presence {
		if present {
			return true
		}
	}
	return false
}
