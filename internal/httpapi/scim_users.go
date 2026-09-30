package httpapi

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"net/mail"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/store"
)

const maxSCIMRequestBytes = 1 << 20

var scimUserNameFilter = regexp.MustCompile(`(?i)^\s*userName\s+eq\s+("(?:\\.|[^"\\])*")\s*$`)
var scimEmailValuePath = regexp.MustCompile(`(?i)^emails(?:\[\s*(?:primary\s+eq\s+true|type\s+eq\s+"work")\s*\])?\.value$`)

type scimName struct {
	Formatted   string `json:"formatted,omitempty"`
	GivenName   string `json:"givenName,omitempty"`
	FamilyName  string `json:"familyName,omitempty"`
}

type scimEmail struct {
	Value   string `json:"value"`
	Type    string `json:"type,omitempty"`
	Primary bool   `json:"primary,omitempty"`
}

type scimUserInput struct {
	Schemas     []string    `json:"schemas,omitempty"`
	ExternalID  *string     `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *scimName   `json:"name,omitempty"`
	DisplayName *string     `json:"displayName,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      *bool       `json:"active,omitempty"`
}

type scimUserMeta struct {
	ResourceType string    `json:"resourceType"`
	Created      time.Time `json:"created"`
	LastModified time.Time `json:"lastModified"`
	Location     string    `json:"location,omitempty"`
}

type scimUserResource struct {
	Schemas     []string    `json:"schemas"`
	ID          string      `json:"id"`
	ExternalID  *string     `json:"externalId,omitempty"`
	UserName    string      `json:"userName"`
	Name        *scimName   `json:"name,omitempty"`
	DisplayName string      `json:"displayName,omitempty"`
	Emails      []scimEmail `json:"emails,omitempty"`
	Active      bool        `json:"active"`
	Meta        scimUserMeta `json:"meta"`
}

type scimUserListResponse struct {
	Schemas      []string            `json:"schemas"`
	TotalResults int64               `json:"totalResults"`
	StartIndex   int                 `json:"startIndex"`
	ItemsPerPage int                 `json:"itemsPerPage"`
	Resources    []scimUserResource  `json:"Resources"`
}

type scimPatchOperation struct {
	Op    string          `json:"op"`
	Path  string          `json:"path,omitempty"`
	Value json.RawMessage `json:"value"`
}

type scimPatchRequest struct {
	Schemas    []string              `json:"schemas,omitempty"`
	Operations []scimPatchOperation  `json:"Operations"`
}

type scimRequestError struct {
	status   int
	scimType string
	detail   string
}

func (e *scimRequestError) Error() string { return e.detail }

func (h *scimHandler) listUsers(w http.ResponseWriter, r *http.Request) {
	if r.URL.Query().Get("sortBy") != "" || r.URL.Query().Get("sortOrder") != "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "SCIM sorting is not supported")
		return
	}
	startIndex, count, ok := parseSCIMPage(r)
	if !ok {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "startIndex and count must be non-negative integers, and startIndex must be at least 1")
		return
	}
	userName, err := parseSCIMUserNameFilter(r.URL.Query().Get("filter"))
	if err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidFilter", "only a userName eq string filter is supported")
		return
	}
	users, total, err := h.listEligibleSCIMUsers(r.Context(), userName, startIndex, count)
	if err != nil {
		h.writeStoreError(w, r, "list users", err)
		return
	}
	resources := make([]scimUserResource, len(users))
	for i := range users {
		resources[i] = scimResourceFromUser(users[i])
	}
	writeSCIMJSON(w, http.StatusOK, scimUserListResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: total,
		StartIndex:   startIndex,
		ItemsPerPage: len(resources),
		Resources:    resources,
	})
}

func (h *scimHandler) listEligibleSCIMUsers(ctx context.Context, userName *string, startIndex, count int) ([]store.SCIMUser, int64, error) {
	const batchSize = 1000
	users := make([]store.SCIMUser, 0, count)
	var total int64
	pageIndex := 1
	for {
		candidates, _, err := store.ListSCIMUsers(ctx, h.q, userName, pageIndex, batchSize)
		if err != nil {
			return nil, 0, err
		}
		for _, candidate := range candidates {
			if err := h.ensureSCIMTarget(ctx, h.q, candidate); err != nil {
				if isProtectedSCIMUserError(err) {
					continue
				}
				return nil, 0, err
			}
			total++
			if count > 0 && total >= int64(startIndex) && len(users) < count {
				users = append(users, candidate)
			}
		}
		if len(candidates) < batchSize {
			break
		}
		pageIndex += len(candidates)
	}
	return users, total, nil
}

func isProtectedSCIMUserError(err error) bool {
	var problem *scimRequestError
	return errors.As(err, &problem) && problem.status == http.StatusForbidden
}

func (h *scimHandler) createUser(w http.ResponseWriter, r *http.Request) {
	var request scimUserInput
	if !decodeSCIMJSON(w, r, &request) {
		return
	}
	userName := strings.TrimSpace(request.UserName)
	if userName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	externalID := nonEmptySCIMExternalID(request.ExternalID)
	if externalID == nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "externalId is required")
		return
	}
	status := "active"
	if request.Active != nil && !*request.Active {
		status = "disabled"
	}
	email := scimPrimaryEmail(request.Emails)
	created := store.SCIMUser{}
	err := store.WithAdminTx(r.Context(), h.q, func(ctx context.Context, tx store.Tx) error {
		if err := validateSCIMEmail(ctx, tx, "", email); err != nil {
			return err
		}
		user, err := store.CreateSCIMUser(ctx, tx, store.User{
			Username:    userName,
			Email:       email,
			DisplayName: scimDisplayName(request.DisplayName, request.Name),
			Status:      status,
		}, externalID)
		if err != nil {
			return err
		}
		created = user
		actorID := "scim"
		if _, err := h.audit.Append(ctx, tx, auditlog.Entry{
			ActorID: &actorID,
			Action:  "user.created",
			Target:  user.ID,
			After:   user,
		}); err != nil {
			return err
		}
		if err := appendPermissionChange(ctx, tx, []string{user.ID}, nil); err != nil {
			return err
		}
		return store.AppendUserLifecycleEvent(ctx, tx, "user.created", nil, &user.User)
	})
	if err != nil {
		h.writeStoreError(w, r, "create user", err)
		return
	}
	location := scimUserLocation(created.ID)
	w.Header().Set("Location", location)
	writeSCIMJSON(w, http.StatusCreated, scimResourceFromUser(created))
}

func (h *scimHandler) getUser(w http.ResponseWriter, r *http.Request) {
	user, err := getSCIMUser(r.Context(), h.q, chi.URLParam(r, "id"))
	if err != nil {
		if isProtectedSCIMUserError(err) {
			writeSCIMError(w, http.StatusNotFound, "", "the requested user was not found")
		} else {
			h.writeStoreError(w, r, "get user", err)
		}
		return
	}
	if err := h.ensureSCIMTarget(r.Context(), h.q, user); err != nil {
		if isProtectedSCIMUserError(err) {
			writeSCIMError(w, http.StatusNotFound, "", "the requested user was not found")
		} else {
			h.writeStoreError(w, r, "get user", err)
		}
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimResourceFromUser(user))
}

func (h *scimHandler) patchUser(w http.ResponseWriter, r *http.Request) {
	var request scimPatchRequest
	if !decodeSCIMJSON(w, r, &request) {
		return
	}
	if len(request.Operations) == 0 {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "at least one PatchOp operation is required")
		return
	}
	id := chi.URLParam(r, "id")
	var updated store.SCIMUser
	err := store.WithAdminTx(r.Context(), h.q, func(ctx context.Context, tx store.Tx) error {
		before, err := getSCIMUser(ctx, tx, id)
		if err != nil {
			return err
		}
		candidate := before.User
		for _, operation := range request.Operations {
			if err := applySCIMPatch(&candidate, operation); err != nil {
				return err
			}
		}
		updated, err = h.updateUserTx(ctx, tx, r, before, candidate, before.ExternalID)
		return err
	})
	if err != nil {
		h.writeStoreError(w, r, "update user", err)
		return
	}
	writeSCIMJSON(w, http.StatusOK, scimResourceFromUser(updated))
}

func (h *scimHandler) replaceUser(w http.ResponseWriter, r *http.Request) {
	var request scimUserInput
	if !decodeSCIMJSON(w, r, &request) {
		return
	}
	userName := strings.TrimSpace(request.UserName)
	if userName == "" {
		writeSCIMError(w, http.StatusBadRequest, "invalidValue", "userName is required")
		return
	}
	id := chi.URLParam(r, "id")
	var updated store.SCIMUser
	err := store.WithAdminTx(r.Context(), h.q, func(ctx context.Context, tx store.Tx) error {
		before, err := getSCIMUser(ctx, tx, id)
		if err != nil {
			return err
		}
		externalID := before.ExternalID
		if request.ExternalID != nil {
			externalID = nonEmptySCIMExternalID(request.ExternalID)
			if externalID == nil {
				return &scimRequestError{status: http.StatusBadRequest, scimType: "invalidValue", detail: "externalId cannot be empty"}
			}
		}
		candidate := before.User
		candidate.Username = userName
		candidate.Email = scimPrimaryEmail(request.Emails)
		candidate.DisplayName = scimDisplayName(request.DisplayName, request.Name)
		candidate.Status = "active"
		if request.Active != nil && !*request.Active {
			candidate.Status = "disabled"
		}
		updated, err = h.updateUserTx(ctx, tx, r, before, candidate, externalID)
		return err
	})
	if err != nil {
		h.writeStoreError(w, r, "replace user", err)
		return
	}
	w.Header().Set("Location", scimUserLocation(updated.ID))
	writeSCIMJSON(w, http.StatusOK, scimResourceFromUser(updated))
}

func (h *scimHandler) deleteUser(w http.ResponseWriter, r *http.Request) {
	id := chi.URLParam(r, "id")
	err := store.WithAdminTx(r.Context(), h.q, func(ctx context.Context, tx store.Tx) error {
		before, err := getSCIMUser(ctx, tx, id)
		if err != nil {
			return err
		}
		candidate := before.User
		candidate.Status = "disabled"
		_, err = h.updateUserTx(ctx, tx, r, before, candidate, before.ExternalID)
		return err
	})
	if err != nil {
		h.writeStoreError(w, r, "disable user", err)
		return
	}
	w.Header().Set("Content-Type", scimMediaType)
	w.WriteHeader(http.StatusNoContent)
}

func (h *scimHandler) updateUserTx(ctx context.Context, tx store.Tx, r *http.Request, before store.SCIMUser, candidate store.User, externalID *string) (store.SCIMUser, error) {
	if err := h.ensureSCIMTarget(ctx, tx, before); err != nil {
		return store.SCIMUser{}, err
	}
	if candidate.Status == "active" && before.Status != "active" && before.Status != "disabled" {
		return store.SCIMUser{}, &scimRequestError{
			status: http.StatusForbidden, scimType: "mutability",
			detail: "only disabled users can be activated through SCIM",
		}
	}
	if !sameSCIMEmail(before.Email, candidate.Email) {
		if err := validateSCIMEmail(ctx, tx, before.ID, candidate.Email); err != nil {
			return store.SCIMUser{}, err
		}
	}
	updated, err := store.UpdateSCIMUser(ctx, tx, candidate, externalID)
	if err != nil {
		return store.SCIMUser{}, err
	}
	if before.Status != updated.Status {
		version, err := store.BumpUserPermVer(ctx, tx, updated.ID)
		if err != nil {
			return store.SCIMUser{}, err
		}
		updated.PermVer = version
		if updated.Status == "disabled" {
			if err := store.ResetFailedLogins(ctx, tx, updated.ID); err != nil {
				return store.SCIMUser{}, err
			}
			updated.FailedLogins = 0
			updated.LockedUntil = nil
			if err := store.RevokeAllUserSessions(ctx, tx, updated.ID, "user_disabled"); err != nil {
				return store.SCIMUser{}, err
			}
			if err := appendUserDisabledEvents(ctx, tx, updated.ID, nil); err != nil {
				return store.SCIMUser{}, err
			}
		} else if err := appendPermissionChange(ctx, tx, []string{updated.ID}, nil); err != nil {
			return store.SCIMUser{}, err
		}
	}
	actorID := "scim"
	if _, err := h.audit.Append(ctx, tx, auditlog.Entry{
		ActorID: &actorID,
		Action:  "user.updated",
		Target:  updated.ID,
		Before:  before,
		After:   updated,
	}); err != nil {
		return store.SCIMUser{}, err
	}
	if err := store.AppendUserLifecycleEvent(ctx, tx, "user.updated", &before.User, &updated.User); err != nil {
		return store.SCIMUser{}, err
	}
	return updated, nil
}

func getSCIMUser(ctx context.Context, q store.Q, id string) (store.SCIMUser, error) {
	user, err := store.GetSCIMUser(ctx, q, id)
	if !errors.Is(err, pgx.ErrNoRows) {
		return user, err
	}
	unscoped, lookupErr := store.GetUser(ctx, q, id)
	if errors.Is(lookupErr, pgx.ErrNoRows) {
		return store.SCIMUser{}, err
	}
	if lookupErr != nil {
		return store.SCIMUser{}, lookupErr
	}
	if isAnonymizedSCIMUser(unscoped) {
		return store.SCIMUser{}, &scimRequestError{status: http.StatusForbidden, detail: "erased users cannot be managed through SCIM"}
	}
	return store.SCIMUser{}, err
}

func isAnonymizedSCIMUser(user store.User) bool {
	if strings.HasPrefix(strings.ToLower(user.Username), "deleted_") {
		return true
	}
	return user.Email != nil && strings.HasSuffix(strings.ToLower(*user.Email), "@deleted.invalid")
}

func (h *scimHandler) ensureSCIMTarget(ctx context.Context, q store.Q, target store.SCIMUser) error {
	if target.ExternalID == nil || isAnonymizedSCIMUser(target.User) {
		return &scimRequestError{status: http.StatusForbidden, detail: "the user is not eligible for SCIM management"}
	}
	if _, err := store.GetCredential(ctx, q, target.ID, "service"); err == nil {
		return &scimRequestError{status: http.StatusForbidden, detail: "service accounts cannot be managed through SCIM"}
	} else if !errors.Is(err, pgx.ErrNoRows) {
		return err
	}
	hasIAMPermission, err := store.UserHasIAMPermission(ctx, q, target.ID)
	if err != nil {
		return err
	}
	if hasIAMPermission {
		return &scimRequestError{status: http.StatusForbidden, detail: "users with effective IAM permissions cannot be managed through SCIM"}
	}
	return nil
}

func validateSCIMEmail(ctx context.Context, q store.Q, excludedUserID string, email *string) error {
	if email == nil {
		return nil
	}
	value := strings.TrimSpace(*email)
	if value == "" {
		return nil
	}
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value {
		return &scimRequestError{status: http.StatusBadRequest, scimType: "invalidValue", detail: "email must be a valid address"}
	}
	taken, err := store.IsEmailTaken(ctx, q, value, excludedUserID)
	if err != nil {
		return err
	}
	if taken {
		return &scimRequestError{status: http.StatusConflict, scimType: "uniqueness", detail: "email is already in use"}
	}
	return nil
}

func sameSCIMEmail(left, right *string) bool {
	if left == nil || right == nil {
		return left == nil && right == nil
	}
	return strings.EqualFold(strings.TrimSpace(*left), strings.TrimSpace(*right))
}

func parseSCIMPage(r *http.Request) (int, int, bool) {
	startIndex := 1
	if raw := strings.TrimSpace(r.URL.Query().Get("startIndex")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 1 {
			return 0, 0, false
		}
		startIndex = value
	}
	count := 100
	if raw := strings.TrimSpace(r.URL.Query().Get("count")); raw != "" {
		value, err := strconv.Atoi(raw)
		if err != nil || value < 0 {
			return 0, 0, false
		}
		count = value
	}
	if count > 1000 {
		count = 1000
	}
	return startIndex, count, true
}

func parseSCIMUserNameFilter(filter string) (*string, error) {
	if strings.TrimSpace(filter) == "" {
		return nil, nil
	}
	matches := scimUserNameFilter.FindStringSubmatch(filter)
	if len(matches) != 2 {
		return nil, errors.New("unsupported SCIM filter")
	}
	var value string
	if err := json.Unmarshal([]byte(matches[1]), &value); err != nil {
		return nil, errors.New("invalid SCIM filter value")
	}
	return &value, nil
}

func decodeSCIMJSON(w http.ResponseWriter, r *http.Request, destination any) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, scimMediaType) {
		writeSCIMError(w, http.StatusUnsupportedMediaType, "", "Content-Type must be application/scim+json")
		return false
	}
	decoder := json.NewDecoder(http.MaxBytesReader(w, r.Body, maxSCIMRequestBytes))
	if err := decoder.Decode(destination); err != nil {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "the SCIM request body is not valid JSON")
		return false
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		writeSCIMError(w, http.StatusBadRequest, "invalidSyntax", "the SCIM request body must contain one JSON value")
		return false
	}
	return true
}

func scimResourceFromUser(user store.SCIMUser) scimUserResource {
	resource := scimUserResource{
		Schemas:    []string{scimUserSchema},
		ID:         user.ID,
		ExternalID: user.ExternalID,
		UserName:   user.Username,
		Active:     user.Status == "active",
		Meta: scimUserMeta{
			ResourceType: "User",
			Created:      user.CreatedAt,
			LastModified: user.UpdatedAt,
			Location:     scimUserLocation(user.ID),
		},
	}
	if user.DisplayName != "" {
		resource.DisplayName = user.DisplayName
		resource.Name = &scimName{Formatted: user.DisplayName}
	}
	if user.Email != nil && *user.Email != "" {
		resource.Emails = []scimEmail{{Value: *user.Email, Type: "work", Primary: true}}
	}
	return resource
}

func scimUserLocation(id string) string {
	return "/scim/v2/Users/" + url.PathEscape(id)
}

func scimPrimaryEmail(emails []scimEmail) *string {
	var first *string
	for _, email := range emails {
		value := strings.TrimSpace(email.Value)
		if value == "" {
			continue
		}
		if email.Primary {
			return &value
		}
		if first == nil {
			first = &value
		}
	}
	return first
}

func scimDisplayName(displayName *string, name *scimName) string {
	if displayName != nil && strings.TrimSpace(*displayName) != "" {
		return strings.TrimSpace(*displayName)
	}
	if name == nil {
		return ""
	}
	if formatted := strings.TrimSpace(name.Formatted); formatted != "" {
		return formatted
	}
	parts := make([]string, 0, 2)
	if given := strings.TrimSpace(name.GivenName); given != "" {
		parts = append(parts, given)
	}
	if family := strings.TrimSpace(name.FamilyName); family != "" {
		parts = append(parts, family)
	}
	return strings.Join(parts, " ")
}

func nonEmptySCIMExternalID(value *string) *string {
	if value == nil || strings.TrimSpace(*value) == "" {
		return nil
	}
	copy := *value
	return &copy
}

func applySCIMPatch(user *store.User, operation scimPatchOperation) error {
	op := strings.ToLower(strings.TrimSpace(operation.Op))
	if op != "replace" && op != "add" && op != "remove" {
		return invalidSCIMPatchValue("only add, remove, and replace operations are supported")
	}
	path := strings.TrimSpace(operation.Path)
	if op == "remove" {
		if path == "" {
			return invalidSCIMPatchPath("a remove operation requires a path")
		}
		return removeSCIMPath(user, path)
	}
	if path == "" {
		var attributes map[string]json.RawMessage
		if err := json.Unmarshal(operation.Value, &attributes); err != nil || len(attributes) == 0 {
			return invalidSCIMPatchValue("a pathless add or replace operation requires an object value")
		}
		keys := make([]string, 0, len(attributes))
		for key := range attributes {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			if err := applySCIMAttribute(user, key, attributes[key]); err != nil {
				return err
			}
		}
		return nil
	}
	return applySCIMPath(user, path, operation.Value)
}

func applySCIMPath(user *store.User, path string, value json.RawMessage) error {
	switch {
	case strings.EqualFold(path, "active"):
		var active *bool
		if err := json.Unmarshal(value, &active); err != nil || active == nil {
			return invalidSCIMPatchValue("active must be a boolean")
		}
		if *active {
			user.Status = "active"
		} else {
			user.Status = "disabled"
		}
		return nil
	case strings.EqualFold(path, "name"):
		var name scimName
		if err := json.Unmarshal(value, &name); err != nil {
			return invalidSCIMPatchValue("name must be an object")
		}
		user.DisplayName = scimDisplayName(nil, &name)
		return nil
	case strings.EqualFold(path, "name.formatted"), strings.EqualFold(path, "displayName"):
		var displayName string
		if err := json.Unmarshal(value, &displayName); err != nil {
			return invalidSCIMPatchValue("name.formatted must be a string")
		}
		user.DisplayName = displayName
		return nil
	case strings.EqualFold(path, "emails"):
		var emails []scimEmail
		if err := json.Unmarshal(value, &emails); err == nil {
			user.Email = scimPrimaryEmail(emails)
			return nil
		}
		var email scimEmail
		if err := json.Unmarshal(value, &email); err != nil {
			return invalidSCIMPatchValue("emails must be an array or object")
		}
		user.Email = scimEmailPointer(email.Value)
		return nil
	case strings.EqualFold(path, "emails.value"), scimEmailValuePath.MatchString(path):
		var email string
		if err := json.Unmarshal(value, &email); err != nil {
			return invalidSCIMPatchValue("email value must be a string")
		}
		user.Email = scimEmailPointer(email)
		return nil
	default:
		return invalidSCIMPatchPath("the PATCH path is not supported")
	}
}

func removeSCIMPath(user *store.User, path string) error {
	switch {
	case strings.EqualFold(path, "emails"), strings.EqualFold(path, "emails.value"), scimEmailValuePath.MatchString(path):
		user.Email = nil
		return nil
	case strings.EqualFold(path, "name"), strings.EqualFold(path, "name.formatted"), strings.EqualFold(path, "displayName"):
		user.DisplayName = ""
		return nil
	default:
		return invalidSCIMPatchPath("the PATCH path is not supported for removal")
	}
}

func applySCIMAttribute(user *store.User, name string, value json.RawMessage) error {
	switch {
	case strings.EqualFold(name, "active"),
		strings.EqualFold(name, "name"),
		strings.EqualFold(name, "displayName"),
		strings.EqualFold(name, "emails"):
		return applySCIMPath(user, name, value)
	default:
		return invalidSCIMPatchPath("the PATCH attribute is not supported")
	}
}

func invalidSCIMPatchValue(detail string) error {
	return &scimRequestError{status: http.StatusBadRequest, scimType: "invalidValue", detail: detail}
}

func invalidSCIMPatchPath(detail string) error {
	return &scimRequestError{status: http.StatusBadRequest, scimType: "invalidPath", detail: detail}
}

func scimEmailPointer(value string) *string {
	value = strings.TrimSpace(value)
	if value == "" {
		return nil
	}
	return &value
}
