package test

import (
	"context"
	"net/http"
	"testing"
	"time"

	"teamusers/internal/store"
)

func TestPasswordHistoryPrunesToMaximumEffectivePolicy(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "password-history-prune-target", "HistoryPruneInitial1")
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":      100,
		"subject_kind":  "user",
		"subject_id":    target.ID,
		"history_count": 2,
	})
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"priority":      10,
		"subject_kind":  "user",
		"subject_id":    target.ID,
		"history_count": 4,
	})

	now := time.Now().UTC()
	for i, hash := range []string{"history-hash-0", "history-hash-1", "history-hash-2", "history-hash-3", "history-hash-4", "history-hash-5"} {
		setAt := now.Add(time.Duration(i) * time.Second)
		if err := store.WithAdminTx(ctx, stack.database.pool, func(ctx context.Context, tx store.Tx) error {
			return store.RecordPasswordHistory(ctx, tx, target.ID, hash, setAt, now)
		}); err != nil {
			t.Fatalf("record password history item %d: %v", i, err)
		}
	}

	got, err := store.ListPasswordHistoryHashes(ctx, stack.database.pool, target.ID, store.PasswordHistoryLimit)
	if err != nil {
		t.Fatalf("list retained password history: %v", err)
	}
	want := []string{"history-hash-5", "history-hash-4", "history-hash-3", "history-hash-2"}
	if len(got) != len(want) {
		t.Fatalf("retained password history = %v, want %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("retained password history = %v, want %v", got, want)
		}
	}
	maxCount, err := store.MaxConfiguredPasswordHistoryCount(ctx, stack.database.pool, target.ID, now)
	if err != nil {
		t.Fatalf("get maximum configured history count: %v", err)
	}
	if maxCount != 4 {
		t.Fatalf("maximum configured history count = %d, want 4", maxCount)
	}
}

func TestPasswordHistoryRejectsReuseOnSelfAndAdminChanges(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	currentPassword := "HistorySelfCurrent1"
	target := seedPasswordUser(t, ctx, stack.database.pool, "password-history-self-target", currentPassword)
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind":  "user",
		"subject_id":    target.ID,
		"history_count": 2,
	})
	targetToken := loginUser(t, stack, target.Username, currentPassword)
	replacement := "HistorySelfReplacement2"
	status, body := stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": currentPassword,
		"new_password":     replacement,
	}, targetToken)
	if status != http.StatusOK {
		t.Fatalf("change password before reuse attempt = %d %s, want 200", status, body)
	}
	targetToken = loginUser(t, stack, target.Username, replacement)
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": replacement,
		"new_password":     currentPassword,
	}, targetToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("reuse prior password on self-service change = %d %s, want 422 weak_password", status, body)
	}

	adminTargetPassword := "HistoryAdminCurrent1"
	adminTarget := seedPasswordUser(t, ctx, stack.database.pool, "password-history-admin-target", adminTargetPassword)
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind":  "user",
		"subject_id":    adminTarget.ID,
		"history_count": 1,
	})
	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+adminTarget.ID+"/credentials", map[string]string{
		"kind":     "password",
		"password": adminTargetPassword,
	}, adminToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("reuse current password on admin credential reset = %d %s, want 422 weak_password", status, body)
	}
}

func TestPasswordHistoryEnforcedOnResetAndInvitationAcceptance(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	resetEmail := "password-history-reset@example.test"
	resetPassword := "HistoryResetCurrent1"
	resetTarget := seedRecoveryUser(t, ctx, stack.database.pool, "password-history-reset", resetEmail, resetPassword)
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind":  "user",
		"subject_id":    resetTarget.ID,
		"history_count": 1,
	})
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/request", map[string]string{"login": resetEmail}, "")
	if status != http.StatusNoContent {
		t.Fatalf("request password reset = %d %s, want 204", status, body)
	}
	resetToken := passwordResetToken(t, stack, resetTarget.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/password-reset/confirm", map[string]string{
		"token":        resetToken,
		"new_password": resetPassword,
	}, "")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("reuse current password on reset completion = %d %s, want 422 weak_password", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "password-history-invitee@example.test",
		"username": "password-history-invitee",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create password-history invitation = %d, want 201: %s", status, body)
	}
	var invitation struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &invitation)
	createPasswordPolicyTestRule(t, stack, adminToken, map[string]any{
		"subject_kind":  "user",
		"subject_id":    invitation.ID,
		"history_count": 1,
	})
	invitationToken := invitationOutboxToken(t, stack, invitation.ID)
	invitedPassword := "HistoryInvitePassword1"
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":        invitationToken,
		"password":     invitedPassword,
		"display_name": "Password History Invitee",
	}, "")
	if status != http.StatusNoContent {
		t.Fatalf("accept invitation with policy-compliant password = %d, want 204: %s", status, body)
	}
	inviteeToken := loginUser(t, stack, "password-history-invitee", invitedPassword)
	status, body = stack.jsonRequest(t, http.MethodPost, "/me/password", map[string]string{
		"current_password": invitedPassword,
		"new_password":     invitedPassword,
	}, inviteeToken)
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("reuse invitation password on self-service change = %d %s, want 422 weak_password", status, body)
	}
}
