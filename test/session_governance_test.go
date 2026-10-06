package test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"teamusers/internal/store"
)

type meActivityPageTestResponse struct {
	Items      []store.LoginActivity `json:"items"`
	NextCursor string                `json:"next_cursor"`
}

func insertSessionTestPolicy(t *testing.T, ctx context.Context, stack *integrationStack, name, subjectKind, subjectID string, priority int, maxSessions, idleTimeoutMinutes *int) {
	t.Helper()
	_, err := stack.database.pool.Exec(ctx, `
		INSERT INTO session_policies (
			id, name, priority, subject_kind, subject_id, max_concurrent_sessions, idle_timeout_minutes
		) VALUES ($1, $2, $3, $4, $5, $6, $7)`,
		store.NewID(), name, priority, subjectKind, subjectID, maxSessions, idleTimeoutMinutes)
	if err != nil {
		t.Fatalf("insert %s session policy: %v", name, err)
	}
}

func TestSessionPolicyResolutionUsesSubjectPriorityAndCleanup(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "session-policy-resolution", "SessionPolicyPassword1")
	team, err := store.CreateTeam(ctx, stack.database.pool, store.Team{
		Slug: "session-policy-team", Name: "Session policy team", Status: "active",
	})
	if err != nil {
		t.Fatalf("create session policy team: %v", err)
	}
	group, err := store.CreateGroup(ctx, stack.database.pool, store.Group{TeamID: team.ID, Name: "Session policy group"})
	if err != nil {
		t.Fatalf("create session policy group: %v", err)
	}
	if err := store.PutMembership(ctx, stack.database.pool, store.Membership{
		TeamID: team.ID, GroupID: group.ID, UserID: user.ID,
	}); err != nil {
		t.Fatalf("add session policy membership: %v", err)
	}
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "session-policy-role"})
	if err != nil {
		t.Fatalf("create session policy role: %v", err)
	}
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: user.ID,
	}); err != nil {
		t.Fatalf("bind session policy role: %v", err)
	}

	defaultMax, defaultIdle := 5, 90
	teamMax := 4
	groupIdle := 45
	roleMax := 2
	insertSessionTestPolicy(t, ctx, stack, "default", "default", "", 0, &defaultMax, &defaultIdle)
	insertSessionTestPolicy(t, ctx, stack, "team", "team", team.ID, 10, &teamMax, nil)
	insertSessionTestPolicy(t, ctx, stack, "group", "group", group.ID, 20, nil, &groupIdle)
	insertSessionTestPolicy(t, ctx, stack, "role", "role", role.ID, 30, &roleMax, nil)

	resolve := func() store.SessionPolicy {
		t.Helper()
		policy, err := store.ResolveSessionPolicy(ctx, stack.database.pool, user.ID, time.Now().UTC())
		if err != nil {
			t.Fatalf("resolve session policy: %v", err)
		}
		return policy
	}
	assertSessionPolicyFields(t, resolve(), 2, 45)

	if err := store.DeleteRole(ctx, stack.database.pool, role.ID); err != nil {
		t.Fatalf("delete role and its session policy: %v", err)
	}
	assertSessionPolicyFields(t, resolve(), 4, 45)
	secondGroup, err := store.CreateGroup(ctx, stack.database.pool, store.Group{TeamID: team.ID, Name: "Session policy retained group"})
	if err != nil {
		t.Fatalf("create retained session policy group: %v", err)
	}
	if err := store.PutMembership(ctx, stack.database.pool, store.Membership{
		TeamID: team.ID, GroupID: secondGroup.ID, UserID: user.ID,
	}); err != nil {
		t.Fatalf("add retained session policy membership: %v", err)
	}
	if err := store.DeleteGroup(ctx, stack.database.pool, group.ID); err != nil {
		t.Fatalf("delete group and its session policy: %v", err)
	}
	assertSessionPolicyFields(t, resolve(), 4, 90)
	if err := store.DeleteTeam(ctx, stack.database.pool, team.ID); err != nil {
		t.Fatalf("delete team and its session policy: %v", err)
	}
	assertSessionPolicyFields(t, resolve(), 5, 90)

	var remaining int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM session_policies WHERE subject_kind IN ('team', 'group', 'role')`).Scan(&remaining); err != nil {
		t.Fatalf("count target session policies: %v", err)
	}
	if remaining != 0 {
		t.Fatalf("remaining target session policies = %d, want 0", remaining)
	}
}

func assertSessionPolicyFields(t *testing.T, policy store.SessionPolicy, maxSessions, idleTimeoutMinutes int) {
	t.Helper()
	if policy.MaxConcurrentSessions == nil || *policy.MaxConcurrentSessions != maxSessions {
		t.Fatalf("resolved max_concurrent_sessions = %v, want %d", policy.MaxConcurrentSessions, maxSessions)
	}
	if policy.IdleTimeoutMinutes == nil || *policy.IdleTimeoutMinutes != idleTimeoutMinutes {
		t.Fatalf("resolved idle_timeout_minutes = %v, want %d", policy.IdleTimeoutMinutes, idleTimeoutMinutes)
	}
}

func TestSessionPolicyEvictsOldestAndRejectsIdleRefresh(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "session-policy-controls", "SessionPolicyPassword2")
	maxSessions, idleTimeoutMinutes := 1, 30
	insertSessionTestPolicy(t, ctx, stack, "controls", "default", "", 100, &maxSessions, &idleTimeoutMinutes)

	first := loginMeTestPair(t, stack, user.Username, "SessionPolicyPassword2")
	firstID := refreshSessionID(first.RefreshToken)
	oldest := time.Now().UTC().Add(-time.Hour)
	if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET created_at = $2 WHERE id = $1`, firstID, oldest); err != nil {
		t.Fatalf("age first session: %v", err)
	}
	second := loginMeTestPair(t, stack, user.Username, "SessionPolicyPassword2")
	secondID := refreshSessionID(second.RefreshToken)

	var firstReason string
	if err := stack.database.pool.QueryRow(ctx, `SELECT revoke_reason FROM sessions WHERE id = $1`, firstID).Scan(&firstReason); err != nil {
		t.Fatalf("read evicted session reason: %v", err)
	}
	if firstReason != "evicted_by_policy" {
		t.Fatalf("first session revoke_reason = %q, want evicted_by_policy", firstReason)
	}
	evictedStatus, evictedBody := stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": first.RefreshToken,
	}, "")
	if evictedStatus != http.StatusUnauthorized {
		t.Fatalf("evicted session refresh status = %d, want %d: %s", evictedStatus, http.StatusUnauthorized, evictedBody)
	}

	status, body := stack.jsonRequest(t, http.MethodGet, "/me/sessions", nil, second.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("list own sessions status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var page struct {
		Items []struct {
			ID           string    `json:"id"`
			LastActiveAt time.Time `json:"last_active_at"`
		} `json:"items"`
		NextCursor string `json:"next_cursor"`
	}
	decodeResponse(t, body, &page)
	if len(page.Items) != 1 || page.Items[0].ID != secondID || page.Items[0].LastActiveAt.IsZero() {
		t.Fatalf("own sessions = %+v, want only second session with last_active_at", page.Items)
	}

	lastActiveBefore := time.Now().UTC().Add(-10 * time.Minute)
	if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET last_active_at = $2 WHERE id = $1`, secondID, lastActiveBefore); err != nil {
		t.Fatalf("backdate second session activity: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": second.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh within idle timeout status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var replacement tokenPair
	decodeResponse(t, body, &replacement)
	assertTokenPair(t, replacement)

	var touchedAt time.Time
	var secondReason string
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT last_active_at, revoke_reason FROM sessions WHERE id = $1`, secondID).Scan(&touchedAt, &secondReason); err != nil {
		t.Fatalf("read rotated session activity: %v", err)
	}
	if !touchedAt.After(lastActiveBefore) || secondReason != "rotated" {
		t.Fatalf("rotated session activity/reason = %s/%q, want activity after %s and rotated", touchedAt, secondReason, lastActiveBefore)
	}

	replacementID := refreshSessionID(replacement.RefreshToken)
	idleSince := time.Now().UTC().Add(-31 * time.Minute)
	if _, err := stack.database.pool.Exec(ctx, `UPDATE sessions SET last_active_at = $2 WHERE id = $1`, replacementID, idleSince); err != nil {
		t.Fatalf("backdate replacement session activity: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": replacement.RefreshToken,
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("idle refresh status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	var idleReason string
	if err := stack.database.pool.QueryRow(ctx, `SELECT revoke_reason FROM sessions WHERE id = $1`, replacementID).Scan(&idleReason); err != nil {
		t.Fatalf("read idle session reason: %v", err)
	}
	if idleReason != "session_idle_expired" {
		t.Fatalf("idle session revoke_reason = %q, want session_idle_expired", idleReason)
	}
	var reuseEvents int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM outbox
		WHERE topic = 'notify.session.reuse_detected' AND payload->>'user_id' = $1`, user.ID).Scan(&reuseEvents); err != nil {
		t.Fatalf("count policy session reuse events: %v", err)
	}
	if reuseEvents != 0 {
		t.Fatalf("policy-driven session revocations emitted %d reuse events, want 0", reuseEvents)
	}
}

func TestMeActivityIsScopedAndCursorPaginated(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	alice := seedPasswordUser(t, ctx, stack.database.pool, "activity-alice", "ActivityPassword1")
	bob := seedPasswordUser(t, ctx, stack.database.pool, "activity-bob", "ActivityPassword2")
	alicePair := loginMeTestPair(t, stack, alice.Username, "ActivityPassword1")

	status, body := stack.jsonRequestHeaders(t, http.MethodPost, "/auth/login", map[string]string{
		"username": alice.Username,
		"password": "WrongActivityPassword1",
	}, "", map[string]string{"User-Agent": "activity-test-agent"})
	if status != http.StatusUnauthorized {
		t.Fatalf("wrong-password login status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "unresolved\nactivity-user",
		"password": "WrongActivityPassword1",
	}, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("unknown-user login status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	_ = loginMeTestPair(t, stack, bob.Username, "ActivityPassword2")

	if status, _ := stack.jsonRequest(t, http.MethodGet, "/me/activity", nil, ""); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated activity status = %d, want %d", status, http.StatusUnauthorized)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/me/activity?limit=1", nil, alicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("first activity page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var firstPage meActivityPageTestResponse
	decodeResponse(t, body, &firstPage)
	if len(firstPage.Items) != 1 || firstPage.NextCursor == "" {
		t.Fatalf("first activity page = %+v, want one row and a next cursor", firstPage)
	}
	first := firstPage.Items[0]
	if first.UserID == nil || *first.UserID != alice.ID || first.Method != "password" || first.Result != "failure" || first.UserAgent != "activity-test-agent" || first.IP == "" {
		t.Fatalf("first own activity = %+v, want Alice's failed password attempt with request metadata", first)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me/activity?limit=2&cursor="+firstPage.NextCursor, nil, alicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("second activity page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var secondPage meActivityPageTestResponse
	decodeResponse(t, body, &secondPage)
	if len(secondPage.Items) != 1 || secondPage.NextCursor != "" {
		t.Fatalf("second activity page = %+v, want one final row", secondPage)
	}
	second := secondPage.Items[0]
	if second.ID >= first.ID || second.UserID == nil || *second.UserID != alice.ID || second.Method != "password" || second.Result != "success" {
		t.Fatalf("second own activity = %+v, want Alice's earlier successful password attempt", second)
	}

	var attemptedUsername string
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT attempted_username FROM login_activity
		WHERE user_id IS NULL AND attempted_username = $1
		ORDER BY id DESC LIMIT 1`, "unresolvedactivity-user").Scan(&attemptedUsername); err != nil {
		t.Fatalf("read unresolved login attempt: %v", err)
	}
	if attemptedUsername != "unresolvedactivity-user" {
		t.Fatalf("stored attempted username = %q, want control-free username", attemptedUsername)
	}

	if status, _ := stack.jsonRequest(t, http.MethodGet, "/me/activity?cursor=invalid", nil, alicePair.AccessToken); status != http.StatusBadRequest {
		t.Fatalf("invalid activity cursor status = %d, want %d", status, http.StatusBadRequest)
	}
	if status, _ := stack.jsonRequest(t, http.MethodGet, "/me/activity?limit=0", nil, alicePair.AccessToken); status != http.StatusBadRequest {
		t.Fatalf("invalid activity limit status = %d, want %d", status, http.StatusBadRequest)
	}
}
