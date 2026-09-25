package test

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"

	"teamusers/internal/store"
)

func TestInvitationCreateAcceptAndReuse(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":        "invitee@example.test",
		"username":     "invitee",
		"display_name": "Invited User",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create invitation status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var invitation struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	decodeResponse(t, body, &invitation)
	if invitation.ID == "" || invitation.Status != "invited" {
		t.Fatalf("create invitation response = %+v", invitation)
	}

	token := invitationOutboxToken(t, stack, invitation.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "invitee",
		"password": "Invitee-password1",
	}, "")
	if status != http.StatusForbidden || !strings.Contains(string(body), "account_pending") {
		t.Fatalf("invited account login = %d %s, want account_pending 403", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":        token,
		"password":     "Invitee-password1",
		"display_name": "Accepted User",
	}, "")
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("accept invitation = %d %q, want empty 204", status, body)
	}

	user, err := store.GetUser(context.Background(), stack.database.pool, invitation.ID)
	if err != nil {
		t.Fatalf("get accepted invitation user: %v", err)
	}
	if user.Status != "active" || user.EmailVerifiedAt == nil || user.DisplayName != "Accepted User" {
		t.Fatalf("accepted invitation user = %+v", user)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": "invitee",
		"password": "Invitee-password1",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("accepted invitation login = %d: %s", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":    token,
		"password": "Invitee-password1",
	}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("reused invitation token = %d %s, want invalid_token 400", status, body)
	}
}

func TestInvitationPasswordResendCancelAndActiveMismatch(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)

	status, body := stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "resend@example.test",
		"username": "resend-user",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create resend invitation = %d: %s", status, body)
	}
	var resend struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &resend)
	oldToken := invitationOutboxToken(t, stack, resend.ID)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":    oldToken,
		"password": "weak",
	}, "")
	if status != http.StatusUnprocessableEntity || !strings.Contains(string(body), "weak_password") {
		t.Fatalf("weak invitation password = %d %s, want weak_password 422", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations/"+resend.ID+"/resend", nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("resend invitation = %d %q, want empty 204", status, body)
	}
	newToken := invitationOutboxToken(t, stack, resend.ID)
	if newToken == oldToken {
		t.Fatal("resend did not rotate invitation token")
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":    oldToken,
		"password": "Resend-password1",
	}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("old resent token = %d %s, want invalid_token 400", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodDelete, "/invitations/"+resend.ID, nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("cancel invitation = %d %q, want empty 204", status, body)
	}
	if _, err := store.GetUser(context.Background(), stack.database.pool, resend.ID); !errors.Is(err, pgx.ErrNoRows) {
		if err == nil {
			t.Fatal("cancelled invitation user still exists")
		}
		t.Fatalf("get cancelled invitation = %v, want no rows", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":    newToken,
		"password": "Resend-password1",
	}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("cancelled invitation token = %d %s, want invalid_token 400", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "active@example.test",
		"username": "active-mismatch",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create active mismatch invitation = %d: %s", status, body)
	}
	var active struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &active)
	activeToken := invitationOutboxToken(t, stack, active.ID)
	status, body = stack.jsonRequest(t, http.MethodPatch, "/users/"+active.ID, map[string]string{"status": "active"}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("promote invitation for mismatch = %d: %s", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token":    activeToken,
		"password": "Active-password1",
	}, "")
	if status != http.StatusBadRequest || !strings.Contains(string(body), "invalid_token") {
		t.Fatalf("active-user invitation token = %d %s, want invalid_token 400", status, body)
	}
}

func TestInvitationAdminPermission(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	nonAdmin := seedPasswordUser(t, context.Background(), stack.database.pool, "non-invitation-admin", "non-admin-password1")
	nonAdminToken := loginUser(t, stack, nonAdmin.Username, "non-admin-password1")

	status, body := stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "forbidden@example.test",
		"username": "forbidden-invite",
	}, nonAdminToken)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin invitation create = %d, want 403: %s", status, body)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email":    "admin-invite@example.test",
		"username": "admin-invite",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("admin invitation create = %d: %s", status, body)
	}
	var invitation struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &invitation)
	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations/"+invitation.ID+"/resend", nil, nonAdminToken)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin invitation resend = %d, want 403: %s", status, body)
	}
	status, body = stack.jsonRequest(t, http.MethodDelete, "/invitations/"+invitation.ID, nil, nonAdminToken)
	if status != http.StatusForbidden {
		t.Fatalf("non-admin invitation cancel = %d, want 403: %s", status, body)
	}
	if admin.ID == nonAdmin.ID {
		t.Fatal("test users unexpectedly share an id")
	}
}

func invitationOutboxToken(t *testing.T, stack *integrationStack, userID string) string {
	t.Helper()
	var payload []byte
	err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload
		FROM outbox
		WHERE topic = 'notify.user.invited' AND payload->>'user_id' = $1
		ORDER BY id DESC
		LIMIT 1`, userID).Scan(&payload)
	if err != nil {
		t.Fatalf("read invitation notification for %s: %v", userID, err)
	}
	var event struct {
		Email string `json:"email"`
		Token string `json:"token"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode invitation notification for %s: %v", userID, err)
	}
	if event.Email == "" || event.Token == "" {
		t.Fatalf("invitation notification for %s = %+v", userID, event)
	}
	return event.Token
}
