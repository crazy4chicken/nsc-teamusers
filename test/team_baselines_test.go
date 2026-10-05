package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"sync"
	"testing"
	"time"

	"teamusers/internal/store"
)

type teamBindingResponse struct {
	ID        string     `json:"id"`
	RoleID    string     `json:"role_id"`
	TeamID    *string    `json:"team_id,omitempty"`
	Condition *string    `json:"condition,omitempty"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

func TestTeamBaselineLifecycleAndScopedAuthorization(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "baseline-member", "BaselineMemberPassword1")
	outsider := seedPasswordUser(t, ctx, stack.database.pool, "baseline-platform", "BaselinePlatformPassword1")

	teamA := createBaselineTestTeam(t, stack, adminToken, "baseline-a")
	teamB := createBaselineTestTeam(t, stack, adminToken, "baseline-b")
	groupA1 := createBaselineTestGroup(t, stack, adminToken, teamA.ID, "baseline-a1")
	groupA2 := createBaselineTestGroup(t, stack, adminToken, teamA.ID, "baseline-a2")
	groupB := createBaselineTestGroup(t, stack, adminToken, teamB.ID, "baseline-b1")
	addBaselineTestMember(t, stack, adminToken, groupA1.ID, target.ID, nil)
	addBaselineTestMember(t, stack, adminToken, groupA2.ID, target.ID, nil)
	addBaselineTestMember(t, stack, adminToken, groupB.ID, target.ID, nil)

	permissionKeys := []string{
		"order:read:team", "order:read:any", "order:delete:team", "!order:delete:team",
		"order:review:team", "iam:bindings:team",
	}
	for _, key := range permissionKeys {
		registerBaselineTestPermission(t, stack, admin, adminToken, key)
	}
	roleA := createBaselineTestRole(t, stack, adminToken, "baseline-role-a", teamA.ID, []string{
		"order:read:team", "order:read:any", "order:delete:team", "!order:delete:team", "iam:bindings:team",
	})
	reviewRole := createBaselineTestRole(t, stack, adminToken, "baseline-role-review", teamA.ID, []string{"order:review:team"})
	roleB := createBaselineTestRole(t, stack, adminToken, "baseline-role-b", teamB.ID, []string{"order:read:team"})
	platformRole := createBaselineTestRole(t, stack, adminToken, "baseline-platform-role", "", []string{"order:read:team"})

	status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"role_id": roleA.ID, "subject_kind": "team", "subject_id": teamA.ID, "team_id": teamB.ID,
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "team baseline requires matching team_id and subject_id") {
		t.Fatalf("mismatched baseline team_id = %d %s, want validation error", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"role_id": roleB.ID, "subject_kind": "team", "subject_id": teamA.ID,
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "team baseline role must belong to the same team") {
		t.Fatalf("foreign-team baseline role = %d %s, want validation error", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"role_id": roleA.ID, "subject_kind": "team", "subject_id": teamA.ID,
		"expires_at": time.Now().UTC().Add(time.Hour).Format(time.RFC3339Nano),
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "team baseline bindings cannot expire") {
		t.Fatalf("expiring baseline = %d %s, want validation error", status, body)
	}

	baselineCondition := `subject.id == "` + target.ID + `"`
	baselineRequest := map[string]any{
		"role_id": roleA.ID, "subject_kind": "team", "subject_id": teamA.ID, "condition": baselineCondition,
	}
	versionBeforeCreate := baselinePermissionVersion(t, stack, target.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", baselineRequest, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create team baseline = %d %s, want 201", status, body)
	}
	var baseline teamBindingResponse
	decodeResponse(t, body, &baseline)
	if baseline.ID == "" || baseline.TeamID == nil || *baseline.TeamID != teamA.ID || baseline.ExpiresAt != nil {
		t.Fatalf("created baseline = %+v, want team scope without expiry", baseline)
	}
	if got := baselinePermissionVersion(t, stack, target.ID); got != versionBeforeCreate+1 {
		t.Fatalf("baseline creation perm_ver = %d, want %d", got, versionBeforeCreate+1)
	}
	assertBaselinePermissionEvent(t, stack, teamA.ID, target.ID)
	assertBaselineAudit(t, stack, "binding.created", baseline.ID)
	hasIAMPermission, err := store.UserHasIAMPermission(ctx, stack.database.pool, target.ID)
	if err != nil || !hasIAMPermission {
		t.Fatalf("conditional team IAM baseline = %t, %v; want effective IAM permission", hasIAMPermission, err)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", baselineRequest, adminToken)
	if status != http.StatusConflict || !strings.Contains(string(body), "a team baseline binding already exists") {
		t.Fatalf("duplicate team baseline = %d %s, want specific conflict", status, body)
	}

	conditionB := `subject.id == "` + target.ID + `"`
	status, body = stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"role_id": roleB.ID, "subject_kind": "team", "subject_id": teamB.ID, "condition": conditionB,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create second team baseline = %d %s, want 201", status, body)
	}
	var baselineB teamBindingResponse
	decodeResponse(t, body, &baselineB)
	if _, err := stack.database.pool.Exec(ctx, `UPDATE role_bindings SET condition = '(' WHERE id = $1`, baselineB.ID); err != nil {
		t.Fatalf("seed invalid condition for second team's baseline: %v", err)
	}

	serviceToken := createBaselineTestServiceToken(t, stack, admin, adminToken)
	check := baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if !check.Allow || check.Reason != "permission granted" {
		t.Fatalf("team A baseline check = %+v, want allow", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamB.ID)
	if check.Allow || check.Reason != "condition_error" || len(check.Matched) != 0 {
		t.Fatalf("applicable invalid baseline condition = %+v, want condition_error", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:delete:team", teamA.ID)
	if check.Allow || check.Reason != "permission denied" || len(check.Matched) != 2 ||
		check.Matched[0] != "!order:delete:team" || check.Matched[1] != "order:delete:team" {
		t.Fatalf("baseline deny precedence = %+v, want sorted allow and deny matches", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:any", teamA.ID)
	if !check.Allow {
		t.Fatalf("team-bound :any grant in its resource team = %+v, want allow", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:any", "")
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("team-bound :any grant without resource team = %+v, want default deny", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", "")
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf(":team request without resource team = %+v, want default deny", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", "team_foreign")
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("foreign-team baseline grant = %+v, want default deny", check)
	}

	platformBindingStatus, platformBindingBody := stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]any{
		"role_id": platformRole.ID, "subject_kind": "user", "subject_id": outsider.ID,
	}, adminToken)
	if platformBindingStatus != http.StatusCreated {
		t.Fatalf("create independent platform binding = %d %s, want 201", platformBindingStatus, platformBindingBody)
	}
	platformCheck := baselineCheck(t, stack, serviceToken, outsider.ID, "order:read:team", teamA.ID)
	if !platformCheck.Allow {
		t.Fatalf("platform grant outside baseline team = %+v, want allow", platformCheck)
	}
	platformCheck = baselineCheck(t, stack, serviceToken, outsider.ID, "order:read:team", "")
	if platformCheck.Allow || platformCheck.Reason != "no matching grant" {
		t.Fatalf("platform :team grant without resource team = %+v, want default deny", platformCheck)
	}

	targetToken := loginUser(t, stack, target.Username, "BaselineMemberPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=team&subject_id="+teamA.ID, nil, targetToken)
	if status != http.StatusOK {
		t.Fatalf("team admin listing own baseline = %d %s, want 200", status, body)
	}
	var baselinePage struct {
		Items []teamBindingResponse `json:"items"`
	}
	decodeResponse(t, body, &baselinePage)
	if len(baselinePage.Items) != 1 || baselinePage.Items[0].ID != baseline.ID ||
		baselinePage.Items[0].TeamID == nil || *baselinePage.Items[0].TeamID != teamA.ID {
		t.Fatalf("team admin baseline list = %+v, want only own team baseline", baselinePage.Items)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=team&subject_id="+teamB.ID, nil, targetToken)
	if status != http.StatusForbidden {
		t.Fatalf("team admin listing foreign baseline = %d %s, want 403", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=team&subject_id="+teamB.ID+"&team_id="+teamA.ID, nil, targetToken)
	if status != http.StatusForbidden {
		t.Fatalf("team admin listing foreign baseline with own team filter = %d %s, want 403", status, body)
	}
	outsiderToken := loginUser(t, stack, outsider.Username, "BaselinePlatformPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=team&subject_id="+teamA.ID, nil, outsiderToken)
	if status != http.StatusForbidden {
		t.Fatalf("nonmember listing team baseline = %d %s, want 403", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"condition": baselineCondition,
	}, targetToken)
	if status != http.StatusOK {
		t.Fatalf("team admin patching own baseline = %d %s, want 200", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"subject_id": teamB.ID,
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "binding identity and scope cannot be changed") {
		t.Fatalf("retargeting a baseline = %d %s, want immutable-scope error", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"expires_at": nil,
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "binding identity and scope cannot be changed") {
		t.Fatalf("changing baseline expiry = %d %s, want immutable-scope error", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"team_id": teamB.ID,
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "binding identity and scope cannot be changed") {
		t.Fatalf("changing baseline team = %d %s, want immutable-scope error", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"subject_kind": "user",
	}, adminToken)
	if status != http.StatusBadRequest || !strings.Contains(string(body), "binding identity and scope cannot be changed") {
		t.Fatalf("changing baseline subject kind = %d %s, want immutable-scope error", status, body)
	}

	versionBeforePatch := baselinePermissionVersion(t, stack, target.ID)
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"condition": `subject.id == "nobody"`,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("replace baseline condition = %d %s, want 200", status, body)
	}
	if got := baselinePermissionVersion(t, stack, target.ID); got != versionBeforePatch+1 {
		t.Fatalf("baseline patch perm_ver = %d, want %d", got, versionBeforePatch+1)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("false baseline condition = %+v, want no matching grant", check)
	}
	hasIAMPermission, err = store.UserHasIAMPermission(ctx, stack.database.pool, target.ID)
	if err != nil || hasIAMPermission {
		t.Fatalf("false conditional team IAM baseline = %t, %v; want no effective IAM permission", hasIAMPermission, err)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"condition": nil,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("clear baseline condition = %d %s, want 200", status, body)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if !check.Allow {
		t.Fatalf("unconditional baseline check = %+v, want allow", check)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"role_id": reviewRole.ID, "condition": nil,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("replace baseline role = %d %s, want 200", status, body)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:review:team", teamA.ID)
	if !check.Allow {
		t.Fatalf("replacement role grant = %+v, want allow", check)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("replaced baseline retained old role grant = %+v", check)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{
		"role_id": roleA.ID, "condition": nil,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("restore baseline role = %d %s, want 200", status, body)
	}

	expiringMember := seedPasswordUser(t, ctx, stack.database.pool, "baseline-expiring-member", "BaselineExpiringPassword1")
	membershipExpiry := time.Now().UTC().Add(2 * time.Hour).Truncate(time.Microsecond)
	addBaselineTestMember(t, stack, adminToken, groupA2.ID, expiringMember.ID, &membershipExpiry)
	snapshotStatus, snapshotBody := stack.jsonRequest(t, http.MethodGet,
		"/authz/permissions/"+expiringMember.ID+"?version=2", nil, serviceToken)
	if snapshotStatus != http.StatusOK {
		t.Fatalf("expiring member v2 snapshot = %d %s, want 200", snapshotStatus, snapshotBody)
	}
	var snapshot permissionsResponse
	decodeResponse(t, snapshotBody, &snapshot)
	if snapshot.Version != 2 || snapshot.UserID != expiringMember.ID || snapshot.ValidUntil == nil {
		t.Fatalf("expiring member snapshot metadata = %+v, want v2 with valid_until", snapshot)
	}
	deadlineDelta := snapshot.ValidUntil.Sub(membershipExpiry)
	if deadlineDelta > time.Microsecond || deadlineDelta < -time.Microsecond {
		t.Fatalf("snapshot valid_until = %s, want membership expiry %s", snapshot.ValidUntil, membershipExpiry)
	}
	for _, grant := range snapshot.Grants {
		if grant.TeamID == nil || *grant.TeamID != teamA.ID {
			t.Fatalf("baseline snapshot grant has invalid team metadata: %+v", grant)
		}
	}

	versionBeforeDisable := baselinePermissionVersion(t, stack, target.ID)
	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+teamA.ID, map[string]string{"status": "disabled"}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("disable baseline team = %d %s, want 200", status, body)
	}
	if got := baselinePermissionVersion(t, stack, target.ID); got != versionBeforeDisable+1 {
		t.Fatalf("team disable perm_ver = %d, want %d", got, versionBeforeDisable+1)
	}
	assertBaselinePermissionEvent(t, stack, teamA.ID, target.ID)
	assertBaselineTeamStatusEvent(t, stack, teamA.ID)
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("disabled team baseline = %+v, want default deny", check)
	}
	platformCheck = baselineCheck(t, stack, serviceToken, outsider.ID, "order:read:team", teamA.ID)
	if !platformCheck.Allow {
		t.Fatalf("platform grant while team is disabled = %+v, want allow", platformCheck)
	}
	// Baseline and team mutations invalidate the earlier token's permission version.
	targetToken = loginUser(t, stack, target.Username, "BaselineMemberPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=team&subject_id="+teamA.ID, nil, targetToken)
	if status != http.StatusForbidden {
		t.Fatalf("team admin access to disabled team baseline = %d %s, want 403", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/bindings/"+baseline.ID, map[string]any{"condition": nil}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("platform admin maintaining disabled baseline = %d %s, want 200", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+teamA.ID, map[string]string{"status": "active"}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("re-enable baseline team = %d %s, want 200", status, body)
	}

	versionBeforeFirstRemoval := baselinePermissionVersion(t, stack, target.ID)
	status, body = stack.jsonRequest(t, http.MethodDelete, "/groups/"+groupA1.ID+"/members/"+target.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("remove first team membership = %d %s, want 204", status, body)
	}
	if got := baselinePermissionVersion(t, stack, target.ID); got != versionBeforeFirstRemoval+1 {
		t.Fatalf("first membership removal perm_ver = %d, want %d", got, versionBeforeFirstRemoval+1)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if !check.Allow {
		t.Fatalf("baseline lost after one of two memberships was removed = %+v", check)
	}
	versionBeforeLastRemoval := baselinePermissionVersion(t, stack, target.ID)
	status, body = stack.jsonRequest(t, http.MethodDelete, "/groups/"+groupA2.ID+"/members/"+target.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("remove last team membership = %d %s, want 204", status, body)
	}
	if got := baselinePermissionVersion(t, stack, target.ID); got != versionBeforeLastRemoval+1 {
		t.Fatalf("last membership removal perm_ver = %d, want %d", got, versionBeforeLastRemoval+1)
	}
	check = baselineCheck(t, stack, serviceToken, target.ID, "order:read:team", teamA.ID)
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("baseline remains after last valid membership removal = %+v", check)
	}
	// Authenticate at the new permission version before checking membership denial.
	targetToken = loginUser(t, stack, target.Username, "BaselineMemberPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, "/bindings?subject_kind=team&subject_id="+teamA.ID, nil, targetToken)
	if status != http.StatusForbidden {
		t.Fatalf("former team admin listing baseline after last membership removal = %d %s, want 403", status, body)
	}

	versionBeforeDelete := baselinePermissionVersion(t, stack, expiringMember.ID)
	status, body = stack.jsonRequest(t, http.MethodDelete, "/bindings/"+baseline.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete team baseline = %d %s, want 204", status, body)
	}
	if got := baselinePermissionVersion(t, stack, expiringMember.ID); got != versionBeforeDelete+1 {
		t.Fatalf("baseline deletion perm_ver = %d, want %d", got, versionBeforeDelete+1)
	}
	assertBaselinePermissionEvent(t, stack, teamA.ID, expiringMember.ID)
	assertBaselineAudit(t, stack, "binding.deleted", baseline.ID)
	check = baselineCheck(t, stack, serviceToken, expiringMember.ID, "order:read:team", teamA.ID)
	if check.Allow || check.Reason != "no matching grant" {
		t.Fatalf("deleted team baseline still grants access = %+v", check)
	}

	if got := baselineAuditCount(t, stack, "binding.updated", baseline.ID); got < 4 {
		t.Fatalf("baseline binding.updated audit count = %d, want at least 4", got)
	}
	assertBaselinePermissionEvent(t, stack, teamA.ID, target.ID)
}

func TestTeamBaselineUniqueIndexRejectsConcurrentCreates(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	team := createBaselineTestTeam(t, stack, adminToken, "baseline-unique-race")
	registerBaselineTestPermission(t, stack, admin, adminToken, "race:read:team")
	role := createBaselineTestRole(t, stack, adminToken, "baseline-race-role", team.ID, []string{"race:read:team"})
	requestBody, err := json.Marshal(map[string]any{
		"role_id": role.ID, "subject_kind": "team", "subject_id": team.ID, "team_id": team.ID,
	})
	if err != nil {
		t.Fatalf("encode concurrent baseline request: %v", err)
	}
	start := make(chan struct{})
	type createResult struct {
		status int
		body   []byte
		err    error
	}
	results := make(chan createResult, 2)
	var workers sync.WaitGroup
	for range 2 {
		workers.Add(1)
		go func() {
			defer workers.Done()
			<-start
			req, err := http.NewRequest(http.MethodPost, stack.baseURL+"/bindings", bytes.NewReader(requestBody))
			if err != nil {
				results <- createResult{err: err}
				return
			}
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("Authorization", "Bearer "+adminToken)
			response, err := stack.client.Do(req)
			if err != nil {
				results <- createResult{err: err}
				return
			}
			body, readErr := io.ReadAll(response.Body)
			_ = response.Body.Close()
			results <- createResult{status: response.StatusCode, body: body, err: readErr}
		}()
	}
	close(start)
	workers.Wait()
	close(results)
	created := 0
	conflicted := 0
	for result := range results {
		if result.err != nil {
			t.Fatalf("concurrent baseline request failed: %v", result.err)
		}
		switch result.status {
		case http.StatusCreated:
			created++
		case http.StatusConflict:
			conflicted++
			if !strings.Contains(string(result.body), "a team baseline binding already exists") {
				t.Fatalf("concurrent baseline conflict = %s, want specific detail", result.body)
			}
		default:
			t.Fatalf("concurrent baseline create = %d %s, want 201 or 409", result.status, result.body)
		}
	}
	if created != 1 || conflicted != 1 {
		t.Fatalf("concurrent baseline results = %d created, %d conflicts; want 1 each", created, conflicted)
	}
}

func createBaselineTestTeam(t *testing.T, stack *integrationStack, token, slug string) teamResponse {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{"slug": slug, "name": slug}, token)
	if status != http.StatusCreated {
		t.Fatalf("create baseline team %q = %d %s, want 201", slug, status, body)
	}
	var team teamResponse
	decodeResponse(t, body, &team)
	return team
}

func createBaselineTestGroup(t *testing.T, stack *integrationStack, token, teamID, name string) groupResponse {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/groups", map[string]string{"team_id": teamID, "name": name}, token)
	if status != http.StatusCreated {
		t.Fatalf("create baseline group %q = %d %s, want 201", name, status, body)
	}
	var group groupResponse
	decodeResponse(t, body, &group)
	return group
}

func registerBaselineTestPermission(t *testing.T, stack *integrationStack, admin store.User, token, key string) {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/permissions", map[string]string{
		"key": key, "description": "team baseline integration permission", "registered_by": admin.ID,
	}, token)
	if status != http.StatusCreated {
		t.Fatalf("register baseline permission %q = %d %s, want 201", key, status, body)
	}
}

func createBaselineTestRole(t *testing.T, stack *integrationStack, token, name, teamID string, permissionKeys []string) roleResponse {
	t.Helper()
	request := map[string]any{"name": name}
	if teamID != "" {
		request["team_id"] = teamID
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/roles", request, token)
	if status != http.StatusCreated {
		t.Fatalf("create baseline role %q = %d %s, want 201", name, status, body)
	}
	var role roleResponse
	decodeResponse(t, body, &role)
	status, body = stack.jsonRequest(t, http.MethodPut, "/roles/"+role.ID+"/permissions", map[string]any{
		"permission_keys": permissionKeys,
	}, token)
	if status != http.StatusOK {
		t.Fatalf("set baseline role %q permissions = %d %s, want 200", name, status, body)
	}
	return role
}

func addBaselineTestMember(t *testing.T, stack *integrationStack, token, groupID, userID string, expiresAt *time.Time) {
	t.Helper()
	request := map[string]any{"user_id": userID}
	if expiresAt != nil {
		request["expires_at"] = expiresAt.UTC().Format(time.RFC3339Nano)
	}
	status, body := stack.jsonRequest(t, http.MethodPut, "/groups/"+groupID+"/members", request, token)
	if status != http.StatusOK {
		t.Fatalf("add baseline membership %s/%s = %d %s, want 200", groupID, userID, status, body)
	}
}

func createBaselineTestServiceToken(t *testing.T, stack *integrationStack, admin store.User, adminToken string) string {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{"kind": "service"}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create baseline service credential = %d %s, want 201", status, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id": credential.ClientID, "client_secret": credential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("create baseline service token = %d %s, want 200", status, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
	return pair.AccessToken
}

func baselineCheck(t *testing.T, stack *integrationStack, serviceToken, userID, permission, teamID string) checkResponse {
	t.Helper()
	request := map[string]any{"subject": userID, "permission": permission}
	if teamID != "" {
		request["context"] = map[string]any{"resource": map[string]string{"team_id": teamID}}
	}
	status, body := stack.jsonRequest(t, http.MethodPost, "/authz/check", request, serviceToken)
	if status != http.StatusOK {
		t.Fatalf("check %s for %s/%s = %d %s, want 200", permission, userID, teamID, status, body)
	}
	var result checkResponse
	decodeResponse(t, body, &result)
	return result
}

func baselinePermissionVersion(t *testing.T, stack *integrationStack, userID string) int64 {
	t.Helper()
	var version int64
	if err := stack.database.pool.QueryRow(context.Background(), `SELECT perm_ver FROM users WHERE id = $1`, userID).Scan(&version); err != nil {
		t.Fatalf("read baseline member perm_ver: %v", err)
	}
	return version
}

func assertBaselinePermissionEvent(t *testing.T, stack *integrationStack, teamID, userID string) {
	t.Helper()
	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload FROM outbox
		WHERE topic = 'perm.changed' AND payload->>'team_id' = $1
		  AND payload->'user_ids' @> jsonb_build_array($2::text)
		ORDER BY id DESC LIMIT 1`, teamID, userID).Scan(&payload); err != nil {
		t.Fatalf("read perm.changed event for team %s user %s: %v", teamID, userID, err)
	}
}

func baselineAuditCount(t *testing.T, stack *integrationStack, action, target string) int {
	t.Helper()
	var count int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE action = $1 AND target = $2`, action, target).Scan(&count); err != nil {
		t.Fatalf("count baseline audit entries: %v", err)
	}
	return count
}

func assertBaselineAudit(t *testing.T, stack *integrationStack, action, target string) {
	t.Helper()
	if count := baselineAuditCount(t, stack, action, target); count == 0 {
		t.Fatalf("audit log has no %s entry for %s", action, target)
	}
}

func assertBaselineTeamStatusEvent(t *testing.T, stack *integrationStack, teamID string) {
	t.Helper()
	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload FROM outbox
		WHERE topic = 'team.updated' AND payload->>'team_id' = $1
		  AND payload->'changed_fields' @> '["status"]'::jsonb
		ORDER BY id DESC LIMIT 1`, teamID).Scan(&payload); err != nil {
		t.Fatalf("read team.updated status event for %s: %v", teamID, err)
	}
	var event struct {
		TeamID        string   `json:"team_id"`
		ChangedFields []string `json:"changed_fields"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode team.updated status event: %v", err)
	}
	if event.TeamID != teamID || len(event.ChangedFields) != 1 || event.ChangedFields[0] != "status" {
		t.Fatalf("team.updated status payload = %+v, want status-only update", event)
	}
}
