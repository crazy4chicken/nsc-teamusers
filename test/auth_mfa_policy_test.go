package test

import (
	"context"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"teamusers/internal/store"
)

func TestConditionalRoleBindingFailsClosedForRequiredMFAPolicy(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "conditional-mfa", "ConditionalMFA1")
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "conditional-mfa-role"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	condition := `resource.attrs["tier"] == "gold"`
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: user.ID, Condition: &condition,
	}); err != nil {
		t.Fatalf("create conditional binding: %v", err)
	}
	policy, err := store.CreateMFAPolicy(ctx, stack.database.pool, store.MFAPolicy{
		Name: "conditional required MFA", Priority: 100, SubjectKind: "role", SubjectID: role.ID, Required: true,
	})
	if err != nil {
		t.Fatalf("create required MFA policy: %v", err)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username, "password": "ConditionalMFA1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("required MFA login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var enrollment struct {
		Required bool   `json:"mfa_enrollment_required"`
		Token    string `json:"mfa_token"`
	}
	decodeResponse(t, body, &enrollment)
	if !enrollment.Required || enrollment.Token == "" {
		t.Fatalf("conditional required MFA response = %+v, want enrollment challenge", enrollment)
	}

	policy.Required = false
	if _, err := store.UpdateMFAPolicy(ctx, stack.database.pool, policy); err != nil {
		t.Fatalf("make MFA policy optional: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username, "password": "ConditionalMFA1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("optional MFA login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var pair tokenPair
	decodeResponse(t, body, &pair)
	assertTokenPair(t, pair)
}

func TestDenyUnenrolledMFAPolicyCanBeCreatedAndPatched(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "deny-unenrolled", "DenyUnenrolled1")
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "deny-unenrolled-role"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: user.ID,
	}); err != nil {
		t.Fatalf("bind role to user: %v", err)
	}

	status, body := stack.jsonRequest(t, http.MethodPost, "/policies/mfa", map[string]any{
		"name": "deny un-enrolled", "priority": 100, "subject_kind": "role", "subject_id": role.ID,
		"required": true, "deny_unenrolled": true,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create deny-unenrolled policy status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var policy struct {
		ID             string `json:"id"`
		DenyUnenrolled bool   `json:"deny_unenrolled"`
	}
	decodeResponse(t, body, &policy)
	if policy.ID == "" || !policy.DenyUnenrolled {
		t.Fatalf("created MFA policy = %+v, want deny_unenrolled=true", policy)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username, "password": "DenyUnenrolled1",
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "mfa_enrollment_denied") {
		t.Fatalf("unenrolled login = %d %s, want mfa_enrollment_denied 403", status, body)
	}
	var method, result string
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT method, result FROM login_activity
		WHERE user_id = $1 ORDER BY id DESC LIMIT 1`, user.ID).Scan(&method, &result); err != nil {
		t.Fatalf("read denied unenrolled MFA activity: %v", err)
	}
	if method != "password" || result != "failure" {
		t.Fatalf("denied unenrolled MFA activity = %q/%q, want password failure", method, result)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/policies/mfa/"+policy.ID, map[string]any{
		"deny_unenrolled": false,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("patch deny-unenrolled policy status = %d, want %d: %s", status, http.StatusOK, body)
	}
	decodeResponse(t, body, &policy)
	if policy.DenyUnenrolled {
		t.Fatalf("patched MFA policy = %+v, want deny_unenrolled=false", policy)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": user.Username, "password": "DenyUnenrolled1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("enrollment-allowed login status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var enrollment struct {
		Required bool `json:"mfa_enrollment_required"`
	}
	decodeResponse(t, body, &enrollment)
	if !enrollment.Required {
		t.Fatalf("login response = %s, want MFA enrollment challenge", body)
	}
}

func TestDeletingMfaSubjectsRemovesPolicies(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()

	team, err := store.CreateTeam(ctx, stack.database.pool, store.Team{
		Slug: "mfa-cleanup-team", Name: "MFA cleanup team", Status: "active",
	})
	if err != nil {
		t.Fatalf("create team: %v", err)
	}
	groupTeam, err := store.CreateTeam(ctx, stack.database.pool, store.Team{
		Slug: "mfa-cleanup-group-team", Name: "MFA cleanup group team", Status: "active",
	})
	if err != nil {
		t.Fatalf("create group team: %v", err)
	}
	group, err := store.CreateGroup(ctx, stack.database.pool, store.Group{TeamID: groupTeam.ID, Name: "MFA cleanup group"})
	if err != nil {
		t.Fatalf("create group: %v", err)
	}
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "MFA cleanup role"})
	if err != nil {
		t.Fatalf("create role: %v", err)
	}

	for _, subject := range []struct {
		kind string
		id   string
	}{
		{kind: "team", id: team.ID},
		{kind: "group", id: group.ID},
		{kind: "role", id: role.ID},
	} {
		policy, err := store.CreateMFAPolicy(ctx, stack.database.pool, store.MFAPolicy{
			Name: "cleanup " + subject.kind, Priority: 100, SubjectKind: subject.kind, SubjectID: subject.id, Required: true,
		})
		if err != nil {
			t.Fatalf("create %s MFA policy: %v", subject.kind, err)
		}
		var deleteSubject func(context.Context, store.Q, string) error
		switch subject.kind {
		case "team":
			deleteSubject = store.DeleteTeam
		case "group":
			deleteSubject = store.DeleteGroup
		case "role":
			deleteSubject = store.DeleteRole
		}
		if err := deleteSubject(ctx, stack.database.pool, subject.id); err != nil {
			t.Fatalf("delete %s: %v", subject.kind, err)
		}
		if _, err := store.GetMFAPolicy(ctx, stack.database.pool, policy.ID); !errors.Is(err, pgx.ErrNoRows) {
			t.Fatalf("policy for deleted %s returned error %v, want pgx.ErrNoRows", subject.kind, err)
		}
	}
}
