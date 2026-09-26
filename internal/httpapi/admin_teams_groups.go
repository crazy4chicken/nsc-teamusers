package httpapi

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

type teamCreateRequest struct {
	Slug   string `json:"slug"`
	Name   string `json:"name"`
	Status string `json:"status,omitempty"`
}

type teamPatchRequest struct {
	Slug   *string `json:"slug,omitempty"`
	Name   *string `json:"name,omitempty"`
	Status *string `json:"status,omitempty"`
}

type groupCreateRequest struct {
	TeamID string `json:"team_id"`
	Name   string `json:"name"`
}

type groupPatchRequest struct {
	TeamID *string `json:"team_id,omitempty"`
	Name   *string `json:"name,omitempty"`
}

type membershipRequest struct {
	UserID    string     `json:"user_id"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func (h *adminHandler) listTeams(w http.ResponseWriter, r *http.Request) {
	cursor, limit, ok := parsePage(w, r)
	if !ok {
		return
	}
	teams, next, err := store.ListTeams(r.Context(), h.q, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeItems(w, teams, next)
}

func (h *adminHandler) getTeam(w http.ResponseWriter, r *http.Request) {
	team, err := store.GetTeam(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, team)
}

func (h *adminHandler) createTeam(w http.ResponseWriter, r *http.Request) {
	var request teamCreateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.Slug = strings.TrimSpace(request.Slug)
	request.Name = strings.TrimSpace(request.Name)
	if request.Slug == "" || request.Name == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "slug and name are required")
		return
	}
	if request.Status == "" {
		request.Status = "active"
	}
	if request.Status != "active" && request.Status != "disabled" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "status must be active or disabled")
		return
	}
	var created store.Team
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		team, err := store.CreateTeam(ctx, tx, store.Team{
			Slug: request.Slug, Name: request.Name, Status: request.Status,
		})
		if err != nil {
			return err
		}
		created = team
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, new(team.ID), "team.created", team.ID, nil, team))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, created)
}

func (h *adminHandler) patchTeam(w http.ResponseWriter, r *http.Request) {
	var request teamPatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.Slug == nil && request.Name == nil && request.Status == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "at least one team field is required")
		return
	}
	id := chi.URLParam(r, "id")
	var updated store.Team
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetTeam(ctx, tx, id)
		if err != nil {
			return err
		}
		original := before
		if request.Slug != nil {
			before.Slug = strings.TrimSpace(*request.Slug)
			if before.Slug == "" {
				return validationError("slug is required")
			}
		}
		if request.Name != nil {
			before.Name = strings.TrimSpace(*request.Name)
			if before.Name == "" {
				return validationError("name is required")
			}
		}
		if request.Status != nil {
			before.Status = strings.TrimSpace(*request.Status)
			if before.Status != "active" && before.Status != "disabled" {
				return validationError("status must be active or disabled")
			}
		}
		updated, err = store.UpdateTeam(ctx, tx, before)
		if err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, new(original.ID), "team.updated", id, original, updated))
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

func (h *adminHandler) deleteTeam(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetTeam(ctx, tx, id)
		if err != nil {
			return err
		}
		userIDs, err := store.ListUserIDsByTeam(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := store.DeleteTeam(ctx, tx, id); err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		teamID := new(before.ID)
		if err := appendPermissionChange(ctx, tx, userIDs, teamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "team.deleted", id, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	teamID := strings.TrimSpace(r.URL.Query().Get("team_id"))
	if teamID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "team_id is required")
		return
	}
	cursor, limit, ok := parsePage(w, r)
	if !ok {
		return
	}
	groups, next, err := store.ListGroups(r.Context(), h.q, teamID, cursor, limit)
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeItems(w, groups, next)
}

func (h *adminHandler) getGroup(w http.ResponseWriter, r *http.Request) {
	group, err := store.GetGroup(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, group)
}

func (h *adminHandler) createGroup(w http.ResponseWriter, r *http.Request) {
	var request groupCreateRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.TeamID = strings.TrimSpace(request.TeamID)
	request.Name = strings.TrimSpace(request.Name)
	if request.TeamID == "" || request.Name == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "team_id and name are required")
		return
	}
	var created store.Group
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		group, err := store.CreateGroup(ctx, tx, store.Group{TeamID: request.TeamID, Name: request.Name})
		if err != nil {
			return err
		}
		created = group
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, new(group.TeamID), "group.created", group.ID, nil, group))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeCreated(w, created)
}

func (h *adminHandler) patchGroup(w http.ResponseWriter, r *http.Request) {
	var request groupPatchRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	if request.TeamID == nil && request.Name == nil {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "at least one group field is required")
		return
	}
	id := chi.URLParam(r, "id")
	var updated store.Group
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		original := before
		if request.TeamID != nil {
			before.TeamID = strings.TrimSpace(*request.TeamID)
			if before.TeamID == "" {
				return validationError("team_id is required")
			}
		}
		if request.Name != nil {
			before.Name = strings.TrimSpace(*request.Name)
			if before.Name == "" {
				return validationError("name is required")
			}
		}
		userIDs, err := store.ListUserIDsByGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		updated, err = store.UpdateGroup(ctx, tx, before)
		if err != nil {
			return err
		}
		if original.TeamID != updated.TeamID {
			if err := store.UpdateGroupMembershipTeam(ctx, tx, id, updated.TeamID); err != nil {
				return err
			}
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		teamID := new(updated.TeamID)
		if err := appendPermissionChange(ctx, tx, userIDs, teamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, new(original.TeamID), "group.updated", id, original, updated))
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

func (h *adminHandler) deleteGroup(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		before, err := store.GetGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		userIDs, err := store.ListUserIDsByGroup(ctx, tx, id)
		if err != nil {
			return err
		}
		if err := store.DeleteGroup(ctx, tx, id); err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, userIDs); err != nil {
			return err
		}
		teamID := new(before.TeamID)
		if err := appendPermissionChange(ctx, tx, userIDs, teamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "group.deleted", id, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (h *adminHandler) putMember(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	var request membershipRequest
	if !decodeJSON(w, r, &request) {
		return
	}
	request.UserID = strings.TrimSpace(request.UserID)
	if request.UserID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "user_id is required")
		return
	}
	var membership store.Membership
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		group, err := store.GetGroup(ctx, tx, groupID)
		if err != nil {
			return err
		}
		if _, err := store.GetUser(ctx, tx, request.UserID); err != nil {
			return err
		}
		before, beforeErr := store.GetMembership(ctx, tx, groupID, request.UserID)
		if beforeErr != nil && !errors.Is(beforeErr, pgx.ErrNoRows) {
			return beforeErr
		}
		membership = store.Membership{TeamID: group.TeamID, GroupID: groupID, UserID: request.UserID, ExpiresAt: request.ExpiresAt}
		if err := store.PutMembership(ctx, tx, membership); err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, []string{request.UserID}); err != nil {
			return err
		}
		teamID := new(group.TeamID)
		if err := appendPermissionChange(ctx, tx, []string{request.UserID}, teamID); err != nil {
			return err
		}
		var beforeValue any
		if beforeErr == nil {
			beforeValue = before
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "membership.created", groupID+"/"+request.UserID, beforeValue, membership))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	writeJSON(w, http.StatusOK, membership)
}

func (h *adminHandler) deleteMember(w http.ResponseWriter, r *http.Request) {
	groupID := chi.URLParam(r, "id")
	userID := strings.TrimSpace(chi.URLParam(r, "userID"))
	if userID == "" {
		var request membershipRequest
		if !decodeJSON(w, r, &request) {
			return
		}
		userID = strings.TrimSpace(request.UserID)
	}
	if userID == "" {
		WriteProblem(w, r, http.StatusBadRequest, "Invalid Request", "user_id is required")
		return
	}
	err := h.withTx(r.Context(), func(ctx context.Context, tx store.Tx) error {
		group, err := store.GetGroup(ctx, tx, groupID)
		if err != nil {
			return err
		}
		before, err := store.GetMembership(ctx, tx, groupID, userID)
		if err != nil {
			return err
		}
		if err := store.DeleteMembership(ctx, tx, groupID, userID); err != nil {
			return err
		}
		if err := bumpUserPermVers(ctx, tx, []string{userID}); err != nil {
			return err
		}
		teamID := new(group.TeamID)
		if err := appendPermissionChange(ctx, tx, []string{userID}, teamID); err != nil {
			return err
		}
		_, err = h.audit.Append(ctx, tx, h.auditEntry(r, teamID, "membership.deleted", groupID+"/"+userID, before, nil))
		return err
	})
	if err != nil {
		WriteStoreProblem(w, r, err)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
