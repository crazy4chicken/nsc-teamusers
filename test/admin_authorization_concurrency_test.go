package test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

func TestConcurrentBindingPartialPatchesSerializeStateAndAudit(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "binding-patch-target", "BindingPatchTargetPassword1")
	roleBefore := createBaselineTestRole(t, stack, adminToken, "binding-patch-before", "", []string{})
	roleAfter := createBaselineTestRole(t, stack, adminToken, "binding-patch-after", "", []string{})
	status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"role_id": roleBefore.ID, "subject_kind": "user", "subject_id": target.ID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create binding for concurrent patch = %d %s, want 201", status, body)
	}
	var binding teamBindingResponse
	decodeResponse(t, body, &binding)

	var permVerBefore int64
	if err := stack.database.pool.QueryRow(ctx, `SELECT perm_ver FROM users WHERE id = $1`, target.ID).Scan(&permVerBefore); err != nil {
		t.Fatalf("read target permission version before concurrent patches: %v", err)
	}

	releaseLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedID string
		return tx.QueryRow(ctx, `SELECT id FROM role_bindings WHERE id = $1 FOR UPDATE`, binding.ID).Scan(&lockedID)
	})
	requestCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 2)
	condition := `subject.kind == "user"`
	launchStepUpTestRequest(requestCtx, stack, results, "binding role patch", http.MethodPatch, "/bindings/"+binding.ID, map[string]string{
		"role_id": roleAfter.ID,
	}, adminToken)
	launchStepUpTestRequest(requestCtx, stack, results, "binding condition patch", http.MethodPatch, "/bindings/"+binding.ID, map[string]string{
		"condition": condition,
	}, adminToken)
	waitForStepUpTestLockWait(t, stack, "role_bindings", 2)
	releaseLock()
	first := awaitStepUpTestRequest(t, requestCtx, results)
	second := awaitStepUpTestRequest(t, requestCtx, results)
	cancel()
	for _, result := range []stepUpTestRequestResult{first, second} {
		if result.status != http.StatusOK {
			t.Fatalf("%s = %d %s, want 200", result.name, result.status, result.body)
		}
	}

	updated, err := store.GetRoleBinding(ctx, stack.database.pool, binding.ID)
	if err != nil {
		t.Fatalf("read binding after concurrent patches: %v", err)
	}
	if updated.RoleID != roleAfter.ID || updated.Condition == nil || *updated.Condition != condition {
		t.Fatalf("binding after concurrent partial patches = role %s condition %v, want role %s and condition %q", updated.RoleID, updated.Condition, roleAfter.ID, condition)
	}
	if updated.TeamID != nil || updated.SubjectKind != "user" || updated.SubjectID != target.ID || updated.ExpiresAt != nil {
		t.Fatalf("binding identity/scope after concurrent patches = team %v kind %s subject %s expiry %v; want unchanged user binding", updated.TeamID, updated.SubjectKind, updated.SubjectID, updated.ExpiresAt)
	}
	var permVerAfter int64
	if err := stack.database.pool.QueryRow(ctx, `SELECT perm_ver FROM users WHERE id = $1`, target.ID).Scan(&permVerAfter); err != nil {
		t.Fatalf("read target permission version after concurrent patches: %v", err)
	}
	if permVerAfter != permVerBefore+2 {
		t.Fatalf("target permission version after concurrent patches = %d, want %d", permVerAfter, permVerBefore+2)
	}

	type bindingState struct {
		RoleID    string  `json:"role_id"`
		Condition *string `json:"condition"`
	}
	type bindingDiff struct {
		Before bindingState `json:"before"`
		After  bindingState `json:"after"`
	}
	rows, err := stack.database.pool.Query(ctx, `
		SELECT diff FROM audit_log WHERE action = 'binding.updated' AND target = $1 ORDER BY id`, binding.ID)
	if err != nil {
		t.Fatalf("read concurrent binding patch audit rows: %v", err)
	}
	defer rows.Close()
	diffs := make([]bindingDiff, 0, 2)
	for rows.Next() {
		var encoded []byte
		if err := rows.Scan(&encoded); err != nil {
			t.Fatalf("scan concurrent binding patch audit row: %v", err)
		}
		var diff bindingDiff
		if err := json.Unmarshal(encoded, &diff); err != nil {
			t.Fatalf("decode concurrent binding patch audit row: %v", err)
		}
		diffs = append(diffs, diff)
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate concurrent binding patch audit rows: %v", err)
	}
	if len(diffs) != 2 {
		t.Fatalf("concurrent binding patch audit row count = %d, want 2", len(diffs))
	}
	equalCondition := func(a, b *string) bool {
		return (a == nil && b == nil) || (a != nil && b != nil && *a == *b)
	}
	expectedRole := roleBefore.ID
	var expectedCondition *string
	for index, diff := range diffs {
		if diff.Before.RoleID != expectedRole || !equalCondition(diff.Before.Condition, expectedCondition) {
			t.Fatalf("binding patch audit before-state %d = role %s condition %v, want role %s condition %v", index, diff.Before.RoleID, diff.Before.Condition, expectedRole, expectedCondition)
		}
		expectedRole = diff.After.RoleID
		expectedCondition = diff.After.Condition
	}
	if expectedRole != roleAfter.ID || expectedCondition == nil || *expectedCondition != condition {
		t.Fatalf("binding patch audit chain ends at role %s condition %v, want role %s condition %q", expectedRole, expectedCondition, roleAfter.ID, condition)
	}
}

func TestConcurrentRoleMoveAndBaselineAssignmentSerialize(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	teamA := createBaselineTestTeam(t, stack, adminToken, "role-baseline-race-a")
	teamB := createBaselineTestTeam(t, stack, adminToken, "role-baseline-race-b")
	role := createBaselineTestRole(t, stack, adminToken, "role-baseline-race", teamA.ID, []string{})

	releaseLock := holdStepUpTestLock(t, stack, func(ctx context.Context, tx pgx.Tx) error {
		var lockedID string
		return tx.QueryRow(ctx, `SELECT id FROM roles WHERE id = $1 FOR UPDATE`, role.ID).Scan(&lockedID)
	})
	requestCtx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	results := make(chan stepUpTestRequestResult, 2)
	launchStepUpTestRequest(requestCtx, stack, results, "role ownership patch", http.MethodPatch, "/roles/"+role.ID, map[string]string{
		"team_id": teamB.ID,
	}, adminToken)
	launchStepUpTestRequest(requestCtx, stack, results, "team baseline assignment", http.MethodPost, "/bindings", map[string]string{
		"role_id": role.ID, "subject_kind": "team", "subject_id": teamA.ID,
	}, adminToken)
	waitForStepUpTestLockWait(t, stack, "role", 2)
	releaseLock()
	first := awaitStepUpTestRequest(t, requestCtx, results)
	second := awaitStepUpTestRequest(t, requestCtx, results)
	cancel()

	var roleResult, bindingResult stepUpTestRequestResult
	for _, result := range []stepUpTestRequestResult{first, second} {
		switch result.name {
		case "role ownership patch":
			roleResult = result
		case "team baseline assignment":
			bindingResult = result
		}
	}
	var baselineCount int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM role_bindings WHERE subject_kind = 'team' AND team_id = $1`, teamA.ID).Scan(&baselineCount); err != nil {
		t.Fatalf("count role race baselines: %v", err)
	}
	updatedRole, err := store.GetRole(context.Background(), stack.database.pool, role.ID)
	if err != nil {
		t.Fatalf("read role after ownership/baseline race: %v", err)
	}
	switch {
	case roleResult.status == http.StatusOK && bindingResult.status == http.StatusBadRequest:
		if !strings.Contains(string(bindingResult.body), "team baseline role must belong to the same team") {
			t.Fatalf("rejected baseline assignment = %s, want ownership mismatch", bindingResult.body)
		}
		if updatedRole.TeamID == nil || *updatedRole.TeamID != teamB.ID || baselineCount != 0 {
			t.Fatalf("role/baseline after serialized move = team %v, baselines %d; want %s, 0", updatedRole.TeamID, baselineCount, teamB.ID)
		}
	case roleResult.status == http.StatusBadRequest && bindingResult.status == http.StatusCreated:
		if !strings.Contains(string(roleResult.body), "team baseline role must belong to the same team") {
			t.Fatalf("rejected role move = %s, want baseline ownership conflict", roleResult.body)
		}
		if updatedRole.TeamID == nil || *updatedRole.TeamID != teamA.ID || baselineCount != 1 {
			t.Fatalf("role/baseline after serialized assignment = team %v, baselines %d; want %s, 1", updatedRole.TeamID, baselineCount, teamA.ID)
		}
	default:
		t.Fatalf("role/baseline race results = role %d %s, binding %d %s; want one successful mutation and one ownership rejection", roleResult.status, roleResult.body, bindingResult.status, bindingResult.body)
	}
}
