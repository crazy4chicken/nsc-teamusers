package test

import (
	"context"
	"net/http"
	"strings"
	"testing"
	"time"

	"teamusers/internal/passwd"
	"teamusers/internal/store"
)

func createPasswordPolicyTestTeam(t *testing.T, stack *integrationStack, token, slug string) teamResponse {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]any{
		"slug": slug,
		"name": slug,
	}, token)
	if status != http.StatusCreated {
		t.Fatalf("create password policy team %q status = %d, want %d: %s", slug, status, http.StatusCreated, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	if team.ID == "" {
		t.Fatalf("created password policy team %q has no id", slug)
	}
	return team
}

func createPasswordPolicyTestGroup(t *testing.T, stack *integrationStack, token, teamID, name string) groupResponse {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/groups", map[string]any{
		"team_id": teamID,
		"name":    name,
	}, token)
	if status != http.StatusCreated {
		t.Fatalf("create password policy group %q status = %d, want %d: %s", name, status, http.StatusCreated, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)
	if group.ID == "" {
		t.Fatalf("created password policy group %q has no id", name)
	}
	return group
}

func createPasswordPolicyTestRole(t *testing.T, stack *integrationStack, token, teamID, name string) roleResponse {
	t.Helper()
	request := map[string]any{"name": name}
	if teamID != "" {
		request["team_id"] = teamID
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/roles", request, token)
	if status != http.StatusCreated {
		t.Fatalf("create password policy role %q status = %d, want %d: %s", name, status, http.StatusCreated, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	if role.ID == "" {
		t.Fatalf("created password policy role %q has no id", name)
	}
	return role
}

func putPasswordPolicyTestMembership(t *testing.T, stack *integrationStack, token, groupID, userID, expiresAt string) {
	t.Helper()
	request := map[string]any{"user_id": userID}
	if expiresAt != "" {
		request["expires_at"] = expiresAt
	}
	status, body := stack.jsonRequest(t, http.MethodPut, "/groups/"+groupID+"/members", request, token)
	if status != http.StatusOK {
		t.Fatalf("put password policy membership group=%s user=%s status = %d, want %d: %s", groupID, userID, status, http.StatusOK, body)
	}
}

func createPasswordPolicyTestBinding(t *testing.T, stack *integrationStack, token, roleID, subjectKind, subjectID, teamID, condition, expiresAt string) string {
	t.Helper()
	request := map[string]any{
		"role_id":      roleID,
		"subject_kind": subjectKind,
		"subject_id":   subjectID,
	}
	if teamID != "" {
		request["team_id"] = teamID
	}
	if condition != "" {
		request["condition"] = condition
	}
	if expiresAt != "" {
		request["expires_at"] = expiresAt
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", request, token)
	if status != http.StatusCreated {
		t.Fatalf("create password policy binding role=%s subject=%s/%s status = %d, want %d: %s", roleID, subjectKind, subjectID, status, http.StatusCreated, body)
	}
	var binding struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &binding)
	if binding.ID == "" {
		t.Fatalf("created password policy binding role=%s subject=%s/%s has no id", roleID, subjectKind, subjectID)
	}
	return binding.ID
}

func createPasswordPolicyTestRule(t *testing.T, stack *integrationStack, token string, request map[string]any) store.PasswordPolicy {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/policies/password", request, token)
	if status != http.StatusCreated {
		t.Fatalf("create password policy status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var policy store.PasswordPolicy
	decodeResponse(t, body, &policy)
	if policy.ID == "" {
		t.Fatal("created password policy has no id")
	}
	return policy
}

func listEffectivePasswordPolicyIDs(t *testing.T, stack *integrationStack, userID string, now time.Time) []string {
	t.Helper()
	policies, err := store.ListEffectivePasswordPolicies(context.Background(), stack.database.pool, userID, now)
	if err != nil {
		t.Fatalf("list effective password policies for %s: %v", userID, err)
	}
	ids := make([]string, len(policies))
	for i, policy := range policies {
		ids[i] = policy.ID
	}
	return ids
}

func insertMismatchedPasswordPolicyGroupBinding(t *testing.T, stack *integrationStack, roleID, groupID, teamID, userID string) string {
	t.Helper()
	bindingID := store.NewID()
	_, err := stack.database.pool.Exec(context.Background(), `
		INSERT INTO role_bindings (id, team_id, role_id, subject_kind, subject_id)
		VALUES ($1, $2, $3, 'group', $4)`, bindingID, teamID, roleID, groupID)
	if err != nil {
		t.Fatalf("insert mismatched password policy group binding for user %s: %v", userID, err)
	}
	return bindingID
}

func TestPasswordPolicyResolutionSemantics(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "password-policy-resolution-target", "ResolutionTargetPassword1")
	other := seedPasswordUser(t, ctx, stack.database.pool, "password-policy-resolution-other", "ResolutionOtherPassword1")

	activeTeam := createPasswordPolicyTestTeam(t, stack, adminToken, "password-policy-active-team")
	activeGroup := createPasswordPolicyTestGroup(t, stack, adminToken, activeTeam.ID, "password-policy-active-group")
	putPasswordPolicyTestMembership(t, stack, adminToken, activeGroup.ID, target.ID, "")

	expiredTeam := createPasswordPolicyTestTeam(t, stack, adminToken, "password-policy-expired-team")
	expiredGroup := createPasswordPolicyTestGroup(t, stack, adminToken, expiredTeam.ID, "password-policy-expired-group")
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	putPasswordPolicyTestMembership(t, stack, adminToken, expiredGroup.ID, target.ID, past)

	mismatchedTeam := createPasswordPolicyTestTeam(t, stack, adminToken, "password-policy-mismatched-team")
	platformRole := createPasswordPolicyTestRole(t, stack, adminToken, "", "password-policy-platform-role")
	teamRole := createPasswordPolicyTestRole(t, stack, adminToken, activeTeam.ID, "password-policy-team-role")
	expiredMembershipBindingRole := createPasswordPolicyTestRole(t, stack, adminToken, expiredTeam.ID, "password-policy-expired-membership-binding-role")
	expiredBindingRole := createPasswordPolicyTestRole(t, stack, adminToken, "", "password-policy-expired-binding-role")
	conditionalRole := createPasswordPolicyTestRole(t, stack, adminToken, "", "password-policy-conditional-role")
	mismatchedRole := createPasswordPolicyTestRole(t, stack, adminToken, "", "password-policy-mismatched-role")

	createPasswordPolicyTestBinding(t, stack, adminToken, platformRole.ID, "user", target.ID, "", "", "")
	createPasswordPolicyTestBinding(t, stack, adminToken, teamRole.ID, "user", target.ID, activeTeam.ID, "", "")
	createPasswordPolicyTestBinding(t, stack, adminToken, expiredMembershipBindingRole.ID, "user", target.ID, expiredTeam.ID, "", "")
	createPasswordPolicyTestBinding(t, stack, adminToken, expiredBindingRole.ID, "user", target.ID, "", "", past)
	createPasswordPolicyTestBinding(t, stack, adminToken, conditionalRole.ID, "user", target.ID, "", "resource.owner_id == subject.id", "")
	insertMismatchedPasswordPolicyGroupBinding(t, stack, mismatchedRole.ID, activeGroup.ID, mismatchedTeam.ID, target.ID)

	directRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     900,
		"subject_kind": "user",
		"subject_id":   target.ID,
	})
	teamRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     800,
		"subject_kind": "team",
		"subject_id":   activeTeam.ID,
	})
	groupRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     700,
		"subject_kind": "group",
		"subject_id":   activeGroup.ID,
	})
	platformRoleRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     600,
		"subject_kind": "role",
		"subject_id":   platformRole.ID,
	})
	teamRoleRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     500,
		"subject_kind": "role",
		"subject_id":   teamRole.ID,
	})
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     1000,
		"subject_kind": "team",
		"subject_id":   expiredTeam.ID,
	})
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     1001,
		"subject_kind": "group",
		"subject_id":   expiredGroup.ID,
	})
	expiredMembershipBindingRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     1001,
		"subject_kind": "role",
		"subject_id":   expiredMembershipBindingRole.ID,
	})
	expiredBindingRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     1002,
		"subject_kind": "role",
		"subject_id":   expiredBindingRole.ID,
	})
	conditionalRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     1003,
		"subject_kind": "role",
		"subject_id":   conditionalRole.ID,
	})
	mismatchedRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     1004,
		"subject_kind": "role",
		"subject_id":   mismatchedRole.ID,
	})
	otherRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     2000,
		"subject_kind": "user",
		"subject_id":   other.ID,
	})
	tieFirst := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     100,
		"subject_kind": "user",
		"subject_id":   target.ID,
		"min_length":   17,
	})
	tieSecond := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":     100,
		"subject_kind": "user",
		"subject_id":   target.ID,
		"min_length":   19,
	})

	gotIDs := listEffectivePasswordPolicyIDs(t, stack, target.ID, time.Now().UTC())
	tieIDs := []string{tieFirst.ID, tieSecond.ID}
	if tieIDs[1] < tieIDs[0] {
		tieIDs[0], tieIDs[1] = tieIDs[1], tieIDs[0]
	}
	wantIDs := append([]string{
		directRule.ID,
		teamRule.ID,
		groupRule.ID,
		platformRoleRule.ID,
		teamRoleRule.ID,
	}, tieIDs...)
	if len(gotIDs) != len(wantIDs) {
		t.Fatalf("effective policy ids = %v, want %v; excluded rules leaked: expired membership binding=%s expired binding=%s conditional=%s mismatched=%s other-user=%s", gotIDs, wantIDs, expiredMembershipBindingRule.ID, expiredBindingRule.ID, conditionalRule.ID, mismatchedRule.ID, otherRule.ID)
	}
	for i := range wantIDs {
		if gotIDs[i] != wantIDs[i] {
			t.Fatalf("effective policy ids = %v, want %v (first mismatch at %d)", gotIDs, wantIDs, i)
		}
	}

	status, body := stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/password-policy", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("resolved tie policy status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var resolved passwd.Policy
	decodeResponse(t, body, &resolved)
	wantMinLength := 17
	if tieSecond.ID < tieFirst.ID {
		wantMinLength = 19
	}
	if resolved.MinLength != wantMinLength {
		t.Fatalf("equal-priority policy resolved min_length = %d, want %d (lower id wins; first=%s second=%s)", resolved.MinLength, wantMinLength, tieFirst.ID, tieSecond.ID)
	}
}

func TestPasswordPolicyFieldLevelMerge(t *testing.T) {
	stack, target, adminToken := func() (*integrationStack, store.User, string) {
		stack, _, adminToken := newAdminSession(t)
		target := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-merge-target", "MergeTargetPassword1")
		return stack, target, adminToken
	}()
	lowPriority := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":      10,
		"subject_kind":  "user",
		"subject_id":    target.ID,
		"require_lower": true,
		"require_upper": true,
	})
	highPriority := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":       20,
		"subject_kind":   "user",
		"subject_id":     target.ID,
		"require_upper":  false,
		"require_symbol": true,
	})

	targetToken := loginUser(t, stack, target.Username, "MergeTargetPassword1")
	status, body := stack.jsonRequest(t, http.MethodGet, "/me/password-policy", nil, targetToken)
	if status != http.StatusOK {
		t.Fatalf("merged password policy status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var policy passwd.Policy
	decodeResponse(t, body, &policy)
	if policy.MinLength != 12 || !policy.RequireLetter || policy.RequireUpper || !policy.RequireLower || !policy.RequireDigit || !policy.RequireSymbol {
		t.Fatalf("merged password policy = %+v, want default min_length=12, letter/digit plus lower and symbol, with high-priority upper=false (low=%s high=%s)", policy, lowPriority.ID, highPriority.ID)
	}
}

func TestPasswordPolicyEnforcement(t *testing.T) {
	stack, target, adminToken := func() (*integrationStack, store.User, string) {
		stack, _, adminToken := newAdminSession(t)
		target := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-enforcement-target", "CurrentPassword1")
		return stack, target, adminToken
	}()
	strictRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":       100,
		"subject_kind":   "user",
		"subject_id":     target.ID,
		"min_length":     20,
		"require_symbol": true,
	})
	targetToken := loginUser(t, stack, target.Username, "CurrentPassword1")
	weakPassword := "WeakPassword1"
	status, body := stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "CurrentPassword1",
		"new_password":     weakPassword,
	}, targetToken)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("weak password under strict rule = %d %s, want 422 weak_password", status, body)
	}

	compliantPassword := "CompliantPassword123!X"
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": "CurrentPassword1",
		"new_password":     compliantPassword,
	}, targetToken)
	if status != http.StatusOK {
		t.Fatalf("compliant password under strict rule = %d %s, want 200", status, body)
	}

	targetToken = loginUser(t, stack, target.Username, compliantPassword)
	status, body = stack.jsonRequest(t, http.MethodDelete, "/policies/password/"+strictRule.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete strict password policy status = %d, want %d: %s", status, http.StatusNoContent, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": compliantPassword,
		"new_password":     weakPassword,
	}, targetToken)
	if status != http.StatusOK {
		t.Fatalf("weak password after strict rule deletion = %d %s, want 200", status, body)
	}
}

func TestPasswordPolicyAdminAPI(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "password-policy-api-target", "PolicyAPITargetPassword1")
	nonAdmin := seedPasswordUser(t, ctx, stack.database.pool, "password-policy-api-non-admin", "PolicyAPINonAdminPassword1")
	nonAdminToken := loginUser(t, stack, nonAdmin.Username, "PolicyAPINonAdminPassword1")

	status, body := stack.jsonRequest(t, http.MethodGet, "/policies/password", nil, nonAdminToken)
	if status != http.StatusForbidden {
		t.Fatalf("password policy list without iam:policies:any = %d, want %d: %s", status, http.StatusForbidden, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/policies/password", map[string]any{
		"subject_kind": "user",
		"subject_id":   target.ID,
	}, nonAdminToken)
	if status != http.StatusForbidden {
		t.Fatalf("password policy create without iam:policies:any = %d, want %d: %s", status, http.StatusForbidden, body)
	}

	missingPath := "/policies/password/does-not-exist"
	missingCases := []struct {
		name   string
		method string
		body   any
	}{
		{name: "get", method: http.MethodGet},
		{name: "patch", method: http.MethodPatch, body: map[string]any{"name": "missing"}},
		{name: "delete", method: http.MethodDelete},
	}
	for _, tc := range missingCases {
		t.Run("missing "+tc.name, func(t *testing.T) {
			status, body := stack.jsonRequest(t, tc.method, missingPath, tc.body, adminToken)
			if status != http.StatusNotFound {
				t.Fatalf("%s %s status = %d, want %d: %s", tc.method, missingPath, status, http.StatusNotFound, body)
			}
		})
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/policies/password", map[string]any{
		"subject_kind": "user",
		"subject_id":   "does-not-exist",
		"min_length":   12,
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("bogus password policy subject = %d, want %d: %s", status, http.StatusUnprocessableEntity, body)
	}
	for _, minLength := range []int{0, 1025} {
		status, body = stack.jsonRequest(t, http.MethodPost, "/policies/password", map[string]any{
			"subject_kind": "user",
			"subject_id":   target.ID,
			"min_length":   minLength,
		}, adminToken)
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("min_length=%d status = %d, want %d: %s", minLength, status, http.StatusUnprocessableEntity, body)
		}
	}
	for _, priority := range []int64{1 << 31, -(1 << 31) - 1} {
		status, body = stack.jsonRequest(t, http.MethodPost, "/policies/password", map[string]any{
			"subject_kind": "user",
			"subject_id":   target.ID,
			"priority":     priority,
		}, adminToken)
		if status != http.StatusUnprocessableEntity {
			t.Fatalf("priority=%d status = %d, want %d: %s", priority, status, http.StatusUnprocessableEntity, body)
		}
	}

	patchRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind":   "user",
		"subject_id":     target.ID,
		"min_length":     20,
		"require_upper":  true,
		"require_symbol": false,
	})
	status, body = stack.jsonRequest(t, http.MethodPatch, "/policies/password/"+patchRule.ID, map[string]any{
		"unexpected_key": true,
	}, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("unknown password policy patch key status = %d, want %d: %s", status, http.StatusBadRequest, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/policies/password/"+patchRule.ID, map[string]any{
		"min_length":    nil,
		"require_upper": nil,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("clear password policy fields status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var patched store.PasswordPolicy
	decodeResponse(t, body, &patched)
	if patched.MinLength != nil || patched.RequireUpper != nil || patched.RequireSymbol == nil || *patched.RequireSymbol {
		t.Fatalf("patched password policy = %+v, want min_length and require_upper cleared while require_symbol remains false", patched)
	}

	auditRule := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"name":         "audited password policy",
		"subject_kind": "user",
		"subject_id":   target.ID,
		"min_length":   13,
	})
	status, body = stack.jsonRequest(t, http.MethodPatch, "/policies/password/"+auditRule.ID, map[string]any{
		"name": "audited password policy updated",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("update audited password policy status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodDelete, "/policies/password/"+auditRule.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete audited password policy status = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/audit?limit=100", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("list audit rows after password policy mutations = %d, want %d: %s", status, http.StatusOK, body)
	}
	var auditLog auditResponse
	decodeResponse(t, body, &auditLog)
	seen := map[string]bool{}
	for _, entry := range auditLog.Items {
		seen[entry.Action] = true
	}
	for _, action := range []string{"password_policy.created", "password_policy.updated", "password_policy.deleted"} {
		if !seen[action] {
			t.Fatalf("audit rows missing %q: %+v", action, auditLog.Items)
		}
	}
}

func TestPasswordPolicyQueryEndpoints(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	target := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-query-target", "QueryTargetPassword1")
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind":  "user",
		"subject_id":    target.ID,
		"min_length":    17,
		"require_upper": true,
	})
	targetToken := loginUser(t, stack, target.Username, "QueryTargetPassword1")
	nonAdmin := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-query-non-admin", "QueryNonAdminPassword1")
	nonAdminToken := loginUser(t, stack, nonAdmin.Username, "QueryNonAdminPassword1")

	status, body := stack.jsonRequest(t, http.MethodGet, "/me/password-policy", nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("GET /me/password-policy without token = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/me/password-policy", nil, targetToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me/password-policy with token = %d, want %d: %s", status, http.StatusOK, body)
	}
	var selfPolicy passwd.Policy
	decodeResponse(t, body, &selfPolicy)
	want := passwd.Policy{MinLength: 17, RequireLetter: true, RequireUpper: true, RequireDigit: true}
	if selfPolicy != want {
		t.Fatalf("self password policy = %+v, want %+v", selfPolicy, want)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/password-policy", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("GET /users/{id}/password-policy = %d, want %d: %s", status, http.StatusOK, body)
	}
	var adminPolicy passwd.Policy
	decodeResponse(t, body, &adminPolicy)
	if adminPolicy != want {
		t.Fatalf("admin password policy = %+v, want %+v", adminPolicy, want)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/does-not-exist/password-policy", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("GET missing user password policy = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/password-policy", nil, nonAdminToken)
	if status != http.StatusForbidden {
		t.Fatalf("GET user password policy without iam:users:any = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}

func TestPasswordPolicyEnforcementOnRewiredPaths(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	defaultAcceptablePassword := "DefaultPassword1"

	credentialTarget := seedPasswordUser(t, ctx, stack.database.pool, "password-policy-credentials-target", "CredentialInitial1")
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   credentialTarget.ID,
		"min_length":   20,
	})
	status, body := stack.jsonRequest(t, http.MethodPost, "/users/"+credentialTarget.ID+"/credentials", map[string]string{
		"kind":     "password",
		"password": defaultAcceptablePassword,
	}, adminToken)
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("default-acceptable admin credential under targeted policy = %d %s, want weak_password 422", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "password-policy-invitee@example.test",
		"username": "password-policy-invitee",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create password-policy invitation = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var invitation struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &invitation)
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   invitation.ID,
		"min_length":   20,
	})
	invitationToken := invitationOutboxToken(t, stack, invitation.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":        invitationToken,
		"password":     defaultAcceptablePassword,
		"display_name": "Policy Invitee",
	}, "")
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("default-acceptable invitation password under targeted policy = %d %s, want weak_password 422", status, body)
	}

	resetEmail := "password-policy-reset@example.test"
	resetTarget := seedRecoveryUser(t, ctx, stack.database.pool, "password-policy-reset", resetEmail, "ResetInitialPassword1")
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   resetTarget.ID,
		"min_length":   20,
	})
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/request", map[string]string{
		"login": resetEmail,
	}, "")
	if status != http.StatusNoContent {
		t.Fatalf("request password reset for policy target = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	resetToken := passwordResetToken(t, stack, resetTarget.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/confirm", map[string]string{
		"token":        resetToken,
		"new_password": defaultAcceptablePassword,
	}, "")
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("default-acceptable reset password under targeted policy = %d %s, want weak_password 422", status, body)
	}
}

func TestPasswordPolicyGroupRoleBindingResolution(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	target := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-group-role-target", "GroupRoleTargetPassword1")
	team := createPasswordPolicyTestTeam(t, stack, adminToken, "password-policy-group-role-team")
	group := createPasswordPolicyTestGroup(t, stack, adminToken, team.ID, "password-policy-group-role-group")
	putPasswordPolicyTestMembership(t, stack, adminToken, group.ID, target.ID, "")

	activeRole := createPasswordPolicyTestRole(t, stack, adminToken, team.ID, "password-policy-active-group-role")
	conditionalRole := createPasswordPolicyTestRole(t, stack, adminToken, team.ID, "password-policy-conditional-group-role")
	expiredRole := createPasswordPolicyTestRole(t, stack, adminToken, team.ID, "password-policy-expired-group-role")
	past := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	createPasswordPolicyTestBinding(t, stack, adminToken, activeRole.ID, "group", group.ID, team.ID, "", "")
	createPasswordPolicyTestBinding(t, stack, adminToken, conditionalRole.ID, "group", group.ID, team.ID, "resource.owner_id == subject.id", "")
	createPasswordPolicyTestBinding(t, stack, adminToken, expiredRole.ID, "group", group.ID, team.ID, "", past)

	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":       50,
		"subject_kind":   "role",
		"subject_id":     activeRole.ID,
		"require_symbol": true,
	})
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":       100,
		"subject_kind":   "role",
		"subject_id":     conditionalRole.ID,
		"require_symbol": false,
	})
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":      90,
		"subject_kind":  "role",
		"subject_id":    expiredRole.ID,
		"require_upper": true,
	})

	status, body := stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/password-policy", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("resolve password policy through group role binding = %d, want %d: %s", status, http.StatusOK, body)
	}
	var resolved passwd.Policy
	decodeResponse(t, body, &resolved)
	want := passwd.Policy{MinLength: 12, RequireLetter: true, RequireDigit: true, RequireSymbol: true}
	if resolved != want {
		t.Fatalf("policy resolved through group bindings = %+v, want %+v (active role applies; conditional and expired roles do not)", resolved, want)
	}
}

func TestPasswordPolicyCascadeCleanup(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	team := createPasswordPolicyTestTeam(t, stack, adminToken, "password-policy-cascade-team")
	group := createPasswordPolicyTestGroup(t, stack, adminToken, team.ID, "password-policy-cascade-group")
	role := createPasswordPolicyTestRole(t, stack, adminToken, team.ID, "password-policy-cascade-role")
	teamPolicy := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "team",
		"subject_id":   team.ID,
	})
	groupPolicy := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "group",
		"subject_id":   group.ID,
	})
	rolePolicy := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "role",
		"subject_id":   role.ID,
	})
	status, body := stack.jsonRequest(t, http.MethodDelete, "/teams/"+team.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete policy team = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	for _, policyID := range []string{teamPolicy.ID, groupPolicy.ID, rolePolicy.ID} {
		status, body = stack.jsonRequest(t, http.MethodGet, "/policies/password/"+policyID, nil, adminToken)
		if status != http.StatusNotFound {
			t.Fatalf("get policy %s after deleting its team = %d, want %d: %s", policyID, status, http.StatusNotFound, body)
		}
	}

	user := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-cascade-user", "CascadeUserPassword1")
	userPolicy := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   user.ID,
	})
	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+user.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete policy user = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/policies/password/"+userPolicy.ID, nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("get policy %s after deleting its user = %d, want %d: %s", userPolicy.ID, status, http.StatusNotFound, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "password-policy-cancel@example.test",
		"username": "password-policy-cancel",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create policy cancellation invitation = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var invitation struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &invitation)
	cancelledUserPolicy := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   invitation.ID,
	})
	status, body = stack.jsonRequest(t, http.MethodDelete, "/invitations/"+invitation.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("cancel policy-targeted invitation = %d, want %d: %s", status, http.StatusNoContent, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/policies/password/"+cancelledUserPolicy.ID, nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("get policy %s after cancelling its invitation = %d, want %d: %s", cancelledUserPolicy.ID, status, http.StatusNotFound, body)
	}
}

func TestPasswordPolicyOrphanManagement(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	target := seedPasswordUser(t, context.Background(), stack.database.pool, "password-policy-orphan-target", "OrphanTargetPassword1")
	policy := createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   target.ID,
		"name":         "orphaned password rule",
		"min_length":   14,
	})
	deleted, err := stack.database.pool.Exec(context.Background(), `DELETE FROM users WHERE id = $1`, target.ID)
	if err != nil {
		t.Fatalf("delete policy subject via legacy path: %v", err)
	}
	if deleted.RowsAffected() != 1 {
		t.Fatalf("legacy user deletion affected %d rows, want 1", deleted.RowsAffected())
	}

	status, body := stack.jsonRequest(t, http.MethodGet, "/policies/password/"+policy.ID, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("get orphaned password policy = %d, want %d: %s", status, http.StatusOK, body)
	}
	var orphaned store.PasswordPolicy
	decodeResponse(t, body, &orphaned)
	if orphaned.ID != policy.ID || orphaned.SubjectKind != "user" || orphaned.SubjectID != target.ID {
		t.Fatalf("orphaned password policy = %+v, want policy for deleted user %s", orphaned, target.ID)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/policies/password/"+policy.ID, map[string]any{
		"name":       "updated orphaned rule",
		"min_length": 18,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("patch orphaned password policy without changing subject = %d, want %d: %s", status, http.StatusOK, body)
	}
	var patched store.PasswordPolicy
	decodeResponse(t, body, &patched)
	if patched.Name != "updated orphaned rule" || patched.SubjectID != target.ID || patched.MinLength == nil || *patched.MinLength != 18 {
		t.Fatalf("patched orphaned password policy = %+v, want rule fields updated without subject change", patched)
	}

	status, body = stack.jsonRequest(t, http.MethodDelete, "/policies/password/"+policy.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete orphaned password policy = %d, want %d: %s", status, http.StatusNoContent, body)
	}
}

func TestPasswordPolicyQueryAllowsPasswordChangeToken(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "password-policy-change-token",
		"email":    "password-policy-change-token@example.test",
		"password": "ProvisionedPassword1",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create provisioned password-policy user = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var target userResponse
	decodeResponse(t, body, &target)
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind": "user",
		"subject_id":   target.ID,
		"min_length":   20,
	})

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": target.Username,
		"password": "ProvisionedPassword1",
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "password_change_required") {
		t.Fatalf("provisioned password-policy login = %d %s, want password_change_required 403", status, body)
	}
	var challenge struct {
		ChangeToken string `json:"change_token"`
	}
	decodeResponse(t, body, &challenge)
	if challenge.ChangeToken == "" {
		t.Fatal("password-change challenge has no change_token")
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me/password-policy", nil, challenge.ChangeToken)
	if status != http.StatusOK {
		t.Fatalf("GET /me/password-policy with password-change token = %d, want %d: %s", status, http.StatusOK, body)
	}
	var policy passwd.Policy
	decodeResponse(t, body, &policy)
	want := passwd.Policy{MinLength: 20, RequireLetter: true, RequireDigit: true}
	if policy != want {
		t.Fatalf("password policy with change token = %+v, want %+v", policy, want)
	}
}
