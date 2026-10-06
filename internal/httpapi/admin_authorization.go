package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"teamusers/internal/domain"
	"teamusers/internal/store"
)

type roleCreateRequest struct {
	TeamID json.RawMessage `json:"team_id,omitempty"`
	Name   string          `json:"name"`
}

type rolePatchRequest struct {
	TeamID json.RawMessage `json:"team_id,omitempty"`
	Name   *string         `json:"name,omitempty"`
}

type setRolePermissionsRequest struct {
	PermissionKeys []string `json:"permission_keys,omitempty"`
	Permissions    []string `json:"permissions,omitempty"`
}

type permissionRequest struct {
	Key          string `json:"key"`
	Description  string `json:"description,omitempty"`
	RegisteredBy string `json:"registered_by"`
}

type bindingRequest struct {
	TeamID      json.RawMessage `json:"team_id,omitempty"`
	RoleID      string          `json:"role_id"`
	SubjectKind string          `json:"subject_kind"`
	SubjectID   string          `json:"subject_id"`
	Condition   *string         `json:"condition,omitempty"`
	ExpiresAt   *time.Time      `json:"expires_at,omitempty"`
}

type bindingPatchRequest struct {
	RoleID      json.RawMessage `json:"role_id"`
	Condition   json.RawMessage `json:"condition"`
	TeamID      json.RawMessage `json:"team_id"`
	SubjectKind json.RawMessage `json:"subject_kind"`
	SubjectID   json.RawMessage `json:"subject_id"`
	ExpiresAt   json.RawMessage `json:"expires_at"`
}

func (h *adminHandler) listRoles(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := ParsePage(w, r)
	if !ok {
		return
	}
	var teamID *string
	if value := strings.TrimSpace(r.URL.Query().Get("team_id")); value != "" {
		teamID = &value
	}
	roles, next, err := store.ListRoles(r.Context(), h.q, teamID, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	WriteItems(w, roles, next)
}

func (h *adminHandler) getRole(w http.ResponseWriter, r *http.Request) {
	role, err := store.GetRole(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, role)
}

func (h *adminHandler) listRolePermissions(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := ParsePage(w, r)
	if !ok {
		return
	}
	roleID := chi.URLParam(r, "id")
	if _, err := store.GetRole(r.Context(), h.q, roleID); err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	permissions, next, err := store.ListRolePermissions(r.Context(), h.q, roleID, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	WriteItems(w, permissions, next)
}

func (h *adminHandler) createRole(w http.ResponseWriter, r *http.Request) {
	var request roleCreateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	name := strings.TrimSpace(request.Name)
	if name == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "name is required")
		return
	}
	teamID, err := decodeNullableString(request.TeamID)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "team_id must be a string or null")
		return
	}
	var created store.Role
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		role, err := store.CreateRole(ctx, tx, store.Role{TeamID: teamID, Name: name})
		if err != nil {
			return err
		}
		created = role
		if err := appendPermissionChange(ctx, tx, nil, teamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "role.created", role.ID, nil, role))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, created)
}

func (h *adminHandler) patchRole(w http.ResponseWriter, r *http.Request) {
	var request rolePatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.TeamID) == 0 && request.Name == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "at least one role field is required")
		return
	}
	id := chi.URLParam(r, "id")
	var updated store.Role
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		// Share the role lock with baseline assignment before checking ownership.
		before, err := store.GetRoleForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		original := before
		if len(request.TeamID) > 0 {
			teamID, decodeErr := decodeNullableString(request.TeamID)
			if decodeErr != nil {
				return validationError("team_id must be a string or null")
			}
			if adminGrantScopeFrom(r.Context()) != adminGrantScopeAny && !sameTeamID(before.TeamID, teamID) {
				return forbiddenError("team-scoped admins cannot change role team_id")
			}
			conflict, err := store.RoleHasForeignTeamBaseline(ctx, tx, id, teamID)
			if err != nil {
				return err
			}
			if conflict {
				return validationError("team baseline role must belong to the same team")
			}
			before.TeamID = teamID
		}
		if request.Name != nil {
			before.Name = strings.TrimSpace(*request.Name)
			if before.Name == "" {
				return validationError("name is required")
			}
		}
		updated, err = store.UpdateRole(ctx, tx, before)
		if err != nil {
			return err
		}
		userIDs, err := store.ListUserIDsByRole(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, userIDs, updated.TeamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, original.TeamID, "role.updated", id, original, updated))
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

func (h *adminHandler) deleteRole(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetRole(ctx, tx, id)
		if err != nil {
			return err
		}
		userIDs, err := store.ListUserIDsByRole(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := store.DeleteRole(ctx, tx, id); err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, userIDs, before.TeamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, before.TeamID, "role.deleted", id, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) setRolePermissions(w http.ResponseWriter, r *http.Request) {
	var request setRolePermissionsRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	permissionKeys := request.PermissionKeys
	if permissionKeys == nil {
		permissionKeys = request.Permissions
	}
	if permissionKeys == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "permission_keys is required")
		return
	}
	for _, key := range permissionKeys {
		permission, err := domain.Parse(key)
		if err != nil {
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Permission", err.Error())
			return
		}
		if adminGrantScopeFrom(r.Context()) != adminGrantScopeAny && permission.Scope != "team" {
			WriteProblem(w, r, http.StatusForbidden, "Forbidden", "team-scoped admins may only attach team-scoped permissions")
			return
		}
	}
	id := chi.URLParam(r, "id")
	var updated []string
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		role, err := store.GetRole(ctx, tx, id)
		if err != nil {
			return err
		}
		for _, key := range permissionKeys {
			if _, err := store.GetPermission(ctx, tx, key); err != nil {
				if errors.Is(err, pgx.ErrNoRows) {
					return unprocessableError("permission is not registered: " + key)
				}
				return err
			}
		}
		before, _, err := store.ListRolePermissions(ctx, tx, id, "", 1000)
		if err != nil {
			return err
		}
		if err := store.SetRolePermissions(ctx, tx, id, permissionKeys); err != nil {
			return err
		}
		updated, _, err = store.ListRolePermissions(ctx, tx, id, "", 1000)
		if err != nil {
			return err
		}
		userIDs, err := store.ListUserIDsByRole(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, userIDs, role.TeamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, role.TeamID, "role.permissions.updated", id, before, updated))
		return err
	})
	if err != nil {
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{"role_id": id, "permissions": updated})
}

func (h *adminHandler) listPermissions(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := ParsePage(w, r)
	if !ok {
		return
	}
	permissions, next, err := store.ListPermissions(r.Context(), h.q, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	WriteItems(w, permissions, next)
}

func (h *adminHandler) getPermission(w http.ResponseWriter, r *http.Request) {
	key := chi.URLParam(r, "key")
	permission, err := store.GetPermission(r.Context(), h.q, key)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, permission)
}

func (h *adminHandler) registerPermission(w http.ResponseWriter, r *http.Request) {
	var request permissionRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Key = strings.TrimSpace(request.Key)
	request.RegisteredBy = strings.TrimSpace(request.RegisteredBy)
	if _, err := domain.Parse(request.Key); err != nil {
		WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Permission", err.Error())
		return
	}
	if request.RegisteredBy == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "registered_by is required")
		return
	}
	var permission store.Permission
	var err error
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, beforeErr := store.GetPermission(ctx, tx, request.Key)
		if beforeErr != nil && !errors.Is(beforeErr, pgx.ErrNoRows) {
			return beforeErr
		}
		permission, err = store.UpsertPermission(ctx, tx, store.Permission{
			Key: request.Key, Description: request.Description, RegisteredBy: request.RegisteredBy,
		})
		if err != nil {
			return err
		}
		if _, err := store.BumpPermissionRegistryPermVer(ctx, tx); err != nil {
			return err
		}
		var beforeValue any
		if beforeErr == nil {
			beforeValue = before
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, nil, "permission.registered", request.Key, beforeValue, permission))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, permission)
}

func (h *adminHandler) listBindings(w http.ResponseWriter, r *http.Request) {
	subjectKind := strings.TrimSpace(r.URL.Query().Get("subject_kind"))
	subjectID := strings.TrimSpace(r.URL.Query().Get("subject_id"))
	if subjectKind != "user" && subjectKind != "group" && subjectKind != "team" || subjectID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "subject_kind and subject_id are required")
		return
	}
	if subjectKind == "team" {
		if _, err := store.GetTeam(r.Context(), h.q, subjectID); err != nil {
			WriteStoreProblem(w, r, err)
			return
		}
	}
	cursor, limit, ok := ParsePage(w, r)
	if !ok {
		return
	}
	bindings, next, err := store.ListRoleBindingsBySubject(r.Context(), h.q, subjectKind, subjectID, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	WriteItems(w, bindings, next)
}

func (h *adminHandler) getBinding(w http.ResponseWriter, r *http.Request) {
	binding, err := store.GetRoleBinding(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, binding)
}

func (h *adminHandler) createBinding(w http.ResponseWriter, r *http.Request) {
	var request bindingRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.RoleID = strings.TrimSpace(request.RoleID)
	request.SubjectKind = strings.TrimSpace(request.SubjectKind)
	request.SubjectID = strings.TrimSpace(request.SubjectID)
	if request.RoleID == "" || request.SubjectID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "role_id and subject_id are required")
		return
	}
	if request.SubjectKind != "user" && request.SubjectKind != "group" && request.SubjectKind != "team" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "subject_kind must be group, user, or team")
		return
	}
	if request.SubjectKind == "team" && request.ExpiresAt != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "team baseline bindings cannot expire")
		return
	}
	requestedTeamID, err := decodeNullableString(request.TeamID)
	if err != nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "team_id must be a string or null")
		return
	}
	if request.Condition != nil {
		if _, err := domain.Compile(*request.Condition); err != nil {
			WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Condition", err.Error())
			return
		}
	}

	var created store.RoleBinding
	err = h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		// Serialize role ownership validation with baseline binding creation.
		role, err := store.GetRoleForUpdate(ctx, tx, request.RoleID)
		if err != nil {
			return err
		}
		teamID := requestedTeamID
		var group store.Group
		switch request.SubjectKind {
		case "user":
			if _, err := store.GetUser(ctx, tx, request.SubjectID); err != nil {
				return err
			}
			if teamID == nil {
				teamID = role.TeamID
			}
		case "group":
			group, err = store.GetGroup(ctx, tx, request.SubjectID)
			if err != nil {
				return err
			}
			if teamID == nil {
				teamID = role.TeamID
			}
			if teamID == nil {
				teamID = &group.TeamID
			}
			if *teamID != group.TeamID {
				return validationError("binding team_id does not match group team_id")
			}
		case "team":
			team, err := store.GetTeam(ctx, tx, request.SubjectID)
			if err != nil {
				return err
			}
			if len(request.TeamID) > 0 && (teamID == nil || *teamID != team.ID) {
				return validationError("team baseline requires matching team_id and subject_id")
			}
			teamID = &team.ID
			if role.TeamID != nil && *role.TeamID != team.ID {
				return validationError("team baseline role must belong to the same team")
			}
		}
		if request.SubjectKind != "team" && role.TeamID != nil && (teamID == nil || *role.TeamID != *teamID) {
			return validationError("binding team_id does not match role team_id")
		}
		if teamID != nil {
			if _, err := store.GetTeam(ctx, tx, *teamID); err != nil {
				return err
			}
		}
		binding, err := store.CreateRoleBinding(ctx, tx, store.RoleBinding{
			TeamID: teamID, RoleID: request.RoleID, SubjectKind: request.SubjectKind,
			SubjectID: request.SubjectID, Condition: request.Condition, ExpiresAt: request.ExpiresAt,
		})
		if err != nil {
			return err
		}
		created = binding
		userIDs, err := store.ListUserIDsByBinding(ctx, tx, binding)
		if err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, userIDs, binding.TeamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, binding.TeamID, "binding.created", binding.ID, nil, binding))
		return err
	})
	if err != nil {
		if isDuplicateTeamBaselineError(err) {
			WriteProblem(w, r, http.StatusConflict, "Conflict", "a team baseline binding already exists")
			return
		}
		if writeValidationError(w, r, err) {
			return
		}
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, created)
}

func isDuplicateTeamBaselineError(err error) bool {
	var pgErr *pgconn.PgError
	return errors.As(err, &pgErr) && pgErr.Code == "23505" && pgErr.ConstraintName == "role_bindings_one_team_baseline_idx"
}

func (h *adminHandler) patchBinding(w http.ResponseWriter, r *http.Request) {
	var request bindingPatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if len(request.TeamID) > 0 || len(request.SubjectKind) > 0 || len(request.SubjectID) > 0 || len(request.ExpiresAt) > 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "binding identity and scope cannot be changed")
		return
	}
	if len(request.RoleID) == 0 && len(request.Condition) == 0 {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "role_id or condition is required")
		return
	}
	roleID := ""
	if len(request.RoleID) > 0 {
		if err := json.Unmarshal(request.RoleID, &roleID); err != nil {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "role_id must be a non-empty string")
			return
		}
		roleID = strings.TrimSpace(roleID)
		if roleID == "" {
			WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "role_id must be a non-empty string")
			return
		}
	}
	var condition *string
	if len(request.Condition) > 0 {
		if strings.TrimSpace(string(request.Condition)) != "null" {
			var value string
			if err := json.Unmarshal(request.Condition, &value); err != nil {
				WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "condition must be a string or null")
				return
			}
			condition = &value
			if _, err := domain.Compile(value); err != nil {
				WriteProblem(w, r, http.StatusUnprocessableEntity, "Invalid Condition", err.Error())
				return
			}
		}
	}

	id := chi.URLParam(r, "id")
	var updated store.RoleBinding
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		var role store.Role
		if roleID != "" {
			// Match baseline creation's role-then-binding lock order.
			lockedRole, roleErr := store.GetRoleForUpdate(ctx, tx, roleID)
			if roleErr != nil {
				return roleErr
			}
			role = lockedRole
		}
		// Merge fields and audit from the row version serialized by this lock.
		before, err := store.GetRoleBindingForUpdate(ctx, tx, id)
		if err != nil {
			return err
		}
		if roleID == "" {
			roleID = before.RoleID
			role, err = store.GetRole(ctx, tx, roleID)
			if err != nil {
				return err
			}
		}
		if len(request.Condition) == 0 {
			condition = before.Condition
		}
		if before.SubjectKind == "team" {
			if role.TeamID != nil && *role.TeamID != before.SubjectID {
				return validationError("team baseline role must belong to the same team")
			}
		} else if role.TeamID != nil && (before.TeamID == nil || *role.TeamID != *before.TeamID) {
			return validationError("binding team_id does not match role team_id")
		}
		userIDs, err := store.ListUserIDsByBinding(ctx, tx, before)
		if err != nil {
			return err
		}
		updated, err = store.UpdateRoleBinding(ctx, tx, store.RoleBinding{
			ID: before.ID, RoleID: roleID, TeamID: before.TeamID, SubjectKind: before.SubjectKind,
			SubjectID: before.SubjectID, Condition: condition, ExpiresAt: before.ExpiresAt,
		})
		if err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, userIDs, updated.TeamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, before.TeamID, "binding.updated", id, before, updated))
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

func (h *adminHandler) deleteBinding(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetRoleBinding(ctx, tx, id)
		if err != nil {
			return err
		}
		userIDs, err := store.ListUserIDsByBinding(ctx, tx, before)
		if err != nil {
			return err
		}
		if err := store.DeleteRoleBinding(ctx, tx, id); err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, userIDs, before.TeamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, before.TeamID, "binding.deleted", id, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func sameTeamID(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return *left == *right
}

func decodeNullableString(raw json.RawMessage) (*string, error) {
	if len(raw) == 0 || string(raw) == "null" {
		return nil, nil
	}
	var value string
	if err := json.Unmarshal(raw, &value); err != nil {
		return nil, err
	}
	value = strings.TrimSpace(value)
	if value == "" {
		return nil, nil
	}
	return &value, nil
}
