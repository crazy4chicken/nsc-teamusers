package test

import (
	"context"
	"encoding/json"
	"net/http"
	"net/url"
	"testing"
)

func TestAdminGroupMembersObservation(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	team := createBaselineTestTeam(t, stack, adminToken, "observation-group-members")
	group := createBaselineTestGroup(t, stack, adminToken, team.ID, "observation-members")
	emptyGroup := createBaselineTestGroup(t, stack, adminToken, team.ID, "observation-empty-members")
	foreignTeam := createBaselineTestTeam(t, stack, adminToken, "observation-foreign-members")
	foreignGroup := createBaselineTestGroup(t, stack, adminToken, foreignTeam.ID, "observation-foreign-group")

	for _, username := range []string{"observation-member-a", "observation-member-b", "observation-member-c"} {
		member := seedPasswordUser(t, context.Background(), stack.database.pool, username, "ObservationMemberPassword1")
		addBaselineTestMember(t, stack, adminToken, group.ID, member.ID, nil)
	}
	foreignMember := seedPasswordUser(t, context.Background(), stack.database.pool,
		"observation-foreign-member", "ObservationForeignPassword1")
	addBaselineTestMember(t, stack, adminToken, foreignGroup.ID, foreignMember.ID, nil)

	status, body := stack.jsonRequest(t, http.MethodGet, "/groups/"+group.ID+"/members?limit=2", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("first group-members page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var firstPage struct {
		Items []struct {
			TeamID  string `json:"team_id"`
			GroupID string `json:"group_id"`
			UserID  string `json:"user_id"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	decodeResponse(t, body, &firstPage)
	if len(firstPage.Items) != 2 {
		t.Fatalf("first group-members page has %d items, want 2", len(firstPage.Items))
	}
	if firstPage.Items[0].UserID >= firstPage.Items[1].UserID {
		t.Fatalf("first group-members page is not ordered by user_id: %+v", firstPage.Items)
	}
	if firstPage.NextCursor != firstPage.Items[1].UserID {
		t.Fatalf("first group-members cursor = %q, want last user_id %q", firstPage.NextCursor, firstPage.Items[1].UserID)
	}
	for _, membership := range firstPage.Items {
		if membership.TeamID != team.ID || membership.GroupID != group.ID || membership.UserID == foreignMember.ID {
			t.Fatalf("first group-members page contains an out-of-scope membership: %+v", membership)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodGet,
		"/groups/"+group.ID+"/members?limit=2&cursor="+url.QueryEscape(firstPage.NextCursor), nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("second group-members page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var secondPage struct {
		Items []struct {
			TeamID  string `json:"team_id"`
			GroupID string `json:"group_id"`
			UserID  string `json:"user_id"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	decodeResponse(t, body, &secondPage)
	if len(secondPage.Items) != 1 || secondPage.NextCursor != "" {
		t.Fatalf("second group-members page = %+v, want one item and no next cursor", secondPage)
	}
	if secondPage.Items[0].TeamID != team.ID || secondPage.Items[0].GroupID != group.ID ||
		secondPage.Items[0].UserID <= firstPage.Items[1].UserID || secondPage.Items[0].UserID == foreignMember.ID {
		t.Fatalf("second group-members page is out of order or scope: %+v", secondPage.Items[0])
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/groups/"+emptyGroup.ID+"/members", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("empty group-members page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var emptyPage struct {
		Items      []json.RawMessage `json:"items"`
		NextCursor string            `json:"next_cursor"`
	}
	decodeResponse(t, body, &emptyPage)
	if emptyPage.Items == nil || len(emptyPage.Items) != 0 || emptyPage.NextCursor != "" {
		t.Fatalf("empty group-members page = %+v, want an empty items array and no cursor", emptyPage)
	}

	for _, limit := range []string{"0", "-1", "invalid"} {
		status, body = stack.jsonRequest(t, http.MethodGet,
			"/groups/"+group.ID+"/members?limit="+url.QueryEscape(limit), nil, adminToken)
		if status != http.StatusBadRequest {
			t.Fatalf("group-members limit %q status = %d, want %d: %s", limit, status, http.StatusBadRequest, body)
		}
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/groups/missing-observation-group/members", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing group-members target status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
}

func TestAdminGroupMemberObservation(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	team := createBaselineTestTeam(t, stack, adminToken, "observation-group-member-detail")
	memberGroup := createBaselineTestGroup(t, stack, adminToken, team.ID, "observation-member-detail")
	otherGroup := createBaselineTestGroup(t, stack, adminToken, team.ID, "observation-other-detail")
	member := seedPasswordUser(t, context.Background(), stack.database.pool,
		"observation-member-detail", "ObservationMemberDetailPassword1")
	addBaselineTestMember(t, stack, adminToken, memberGroup.ID, member.ID, nil)

	status, body := stack.jsonRequest(t, http.MethodGet,
		"/groups/"+memberGroup.ID+"/members/"+member.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get group-member detail status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var membership struct {
		TeamID  string `json:"team_id"`
		GroupID string `json:"group_id"`
		UserID  string `json:"user_id"`
	}
	decodeResponse(t, body, &membership)
	if membership.TeamID != team.ID || membership.GroupID != memberGroup.ID || membership.UserID != member.ID {
		t.Fatalf("group-member detail = %+v", membership)
	}
	assertObservationJSONFields(t, body, []string{"team_id", "group_id", "user_id"})

	status, body = stack.jsonRequest(t, http.MethodGet,
		"/groups/"+otherGroup.ID+"/members/"+member.ID, nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("membership found through wrong group status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet,
		"/groups/"+memberGroup.ID+"/members/missing-observation-user", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing group-member detail status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
}

func TestAdminAssociationObservationAuthorization(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	for _, key := range []string{"iam:groups:team", "iam:bindings:team", "!iam:groups:team"} {
		registerBaselineTestPermission(t, stack, admin, adminToken, key)
	}

	alpha := createBaselineTestTeam(t, stack, adminToken, "observation-scope-alpha")
	beta := createBaselineTestTeam(t, stack, adminToken, "observation-scope-beta")
	disabled := createBaselineTestTeam(t, stack, adminToken, "observation-scope-disabled")
	delegate := seedPasswordUser(t, context.Background(), stack.database.pool,
		"observation-scope-delegate", "ObservationScopeDelegatePassword1")
	target := seedPasswordUser(t, context.Background(), stack.database.pool,
		"observation-scope-target", "ObservationScopeTargetPassword1")

	alphaGroup := createBaselineTestGroup(t, stack, adminToken, alpha.ID, "observation-scope-alpha-group")
	betaGroup := createBaselineTestGroup(t, stack, adminToken, beta.ID, "observation-scope-beta-group")
	disabledGroup := createBaselineTestGroup(t, stack, adminToken, disabled.ID, "observation-scope-disabled-group")
	addBaselineTestMember(t, stack, adminToken, alphaGroup.ID, delegate.ID, nil)

	alphaRole := createBaselineTestRole(t, stack, adminToken, "observation-scope-alpha-role", alpha.ID,
		[]string{"iam:groups:team", "iam:bindings:team"})
	betaRole := createBaselineTestRole(t, stack, adminToken, "observation-scope-beta-role", beta.ID, []string{})
	disabledRole := createBaselineTestRole(t, stack, adminToken, "observation-scope-disabled-role", disabled.ID, []string{})
	platformRole := createBaselineTestRole(t, stack, adminToken, "observation-scope-platform-role", "", []string{})

	createObservationBinding(t, stack, adminToken, alpha.ID, alphaRole.ID, delegate.ID)
	alphaBindingID := createObservationBinding(t, stack, adminToken, alpha.ID, alphaRole.ID, target.ID)
	betaBindingID := createObservationBinding(t, stack, adminToken, beta.ID, betaRole.ID, target.ID)
	disabledBindingID := createObservationBinding(t, stack, adminToken, disabled.ID, disabledRole.ID, target.ID)
	platformBindingID := createObservationBinding(t, stack, adminToken, "", platformRole.ID, target.ID)

	status, body := stack.jsonRequest(t, http.MethodPatch, "/teams/"+disabled.ID,
		map[string]string{"status": "disabled"}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("disable observation target team status = %d, want %d: %s", status, http.StatusOK, body)
	}

	delegateToken := loginUser(t, stack, delegate.Username, "ObservationScopeDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/groups/"+alphaGroup.ID+"/members", nil, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("same-team group-members read status = %d, want %d: %s", status, http.StatusOK, body)
	}
	for _, groupID := range []string{betaGroup.ID, disabledGroup.ID} {
		status, body = stack.jsonRequest(t, http.MethodGet, "/groups/"+groupID+"/members", nil, delegateToken)
		if status != http.StatusForbidden {
			t.Fatalf("foreign or disabled group-members read for %s = %d, want %d: %s", groupID, status, http.StatusForbidden, body)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings/"+alphaBindingID, nil, delegateToken)
	if status != http.StatusOK {
		t.Fatalf("same-team binding detail status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertObservationJSONFields(t, body, []string{"id", "team_id", "role_id", "subject_kind", "subject_id"})
	for _, bindingID := range []string{betaBindingID, disabledBindingID, platformBindingID} {
		status, body = stack.jsonRequest(t, http.MethodGet, "/bindings/"+bindingID, nil, delegateToken)
		if status != http.StatusForbidden {
			t.Fatalf("foreign, disabled, or platform binding detail for %s = %d, want %d: %s", bindingID, status, http.StatusForbidden, body)
		}
	}

	for _, path := range []string{
		"/groups/" + disabledGroup.ID + "/members",
		"/bindings/" + disabledBindingID,
		"/bindings/" + platformBindingID,
	} {
		status, body = stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
		if status != http.StatusOK {
			t.Fatalf("platform-any observation read %s status = %d, want %d: %s", path, status, http.StatusOK, body)
		}
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings/missing-observation-binding", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing binding detail status = %d, want %d: %s", status, http.StatusNotFound, body)
	}

	denyRole := createBaselineTestRole(t, stack, adminToken, "observation-scope-alpha-deny-role", alpha.ID,
		[]string{"!iam:groups:team"})
	createObservationBinding(t, stack, adminToken, alpha.ID, denyRole.ID, delegate.ID)
	delegateToken = loginUser(t, stack, delegate.Username, "ObservationScopeDelegatePassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/groups/"+alphaGroup.ID+"/members", nil, delegateToken)
	if status != http.StatusForbidden {
		t.Fatalf("explicit team-scope deny group-members read status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}

func TestAdminPermissionObservation(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	keys := []string{
		"observation:read:team",
		"!observation:delete:team",
		"observation:*:*",
	}
	for _, key := range keys {
		status, body := stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
			"key": key, "description": "permission observation", "registered_by": admin.ID,
		}, adminToken)
		if status != http.StatusCreated {
			t.Fatalf("register observation permission %q status = %d, want %d: %s", key, status, http.StatusCreated, body)
		}
		status, body = stack.jsonRequest(t, http.MethodGet, "/permissions/"+key, nil, adminToken)
		if status != http.StatusOK {
			t.Fatalf("get observation permission %q status = %d, want %d: %s", key, status, http.StatusOK, body)
		}
		var permission struct {
			Key          string `json:"key"`
			Description  string `json:"description"`
			RegisteredBy string `json:"registered_by"`
		}
		decodeResponse(t, body, &permission)
		if permission.Key != key || permission.Description != "permission observation" || permission.RegisteredBy != admin.ID {
			t.Fatalf("permission detail for %q = %+v", key, permission)
		}
		assertObservationJSONFields(t, body, []string{"key", "description", "registered_by", "created_at"})
	}
	status, body := stack.jsonRequest(t, http.MethodGet, "/permissions/missing-observation:read:any", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing permission detail status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/permissions/not-a-valid-permission-key", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("invalid permission detail key status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
}

func createObservationBinding(t *testing.T, stack *integrationStack, token, teamID, roleID, subjectID string) string {
	t.Helper()
	request := map[string]any{
		"role_id": roleID, "subject_kind": "user", "subject_id": subjectID,
	}
	if teamID != "" {
		request["team_id"] = teamID
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", request, token)
	if status != http.StatusCreated {
		t.Fatalf("create observation binding for team %q = %d %s, want 201", teamID, status, body)
	}
	var binding struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &binding)
	if binding.ID == "" {
		t.Fatal("created observation binding has no id")
	}
	return binding.ID
}

func assertObservationJSONFields(t *testing.T, body []byte, expected []string) {
	t.Helper()
	var fields map[string]json.RawMessage
	decodeResponse(t, body, &fields)
	if len(fields) != len(expected) {
		t.Fatalf("observation response has fields %v, want exactly %v", fields, expected)
	}
	for _, name := range expected {
		if _, ok := fields[name]; !ok {
			t.Fatalf("observation response is missing safe field %q: %s", name, body)
		}
	}
}
