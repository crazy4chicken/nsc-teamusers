package test

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"teamusers/internal/store"
)

type userCredentialObservationPage struct {
	Items      []map[string]json.RawMessage `json:"items"`
	NextCursor string                       `json:"next_cursor"`
}

type userInvitationObservationResponse struct {
	UserStatus string     `json:"user_status"`
	CreatedAt  time.Time  `json:"created_at"`
	ExpiresAt  time.Time  `json:"expires_at"`
	UsedAt     *time.Time `json:"used_at"`
}

func TestAdminUserCredentialMetadataObservation(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := createUserObservationTestUser(t, stack, "credential-observation-target")
	credentialKinds := []string{"password", "service", "totp", "totp_pending", "backup_codes", store.PasskeyCredentialKind}
	for index, kind := range credentialKinds {
		rotatedAt := time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC).Add(time.Duration(index) * time.Hour)
		if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
			UserID: target.ID, Kind: kind, Hash: "observation-secret-hash-" + kind,
			MustChange: kind == "password", RotatedAt: &rotatedAt,
		}); err != nil {
			t.Fatalf("create %s observation credential: %v", kind, err)
		}
	}

	path := "/users/" + target.ID + "/credentials"
	status, body := stack.jsonRequest(t, http.MethodGet, path, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("credentials without token status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/missing-observation-user/credentials", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing user credentials status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	for _, invalidLimit := range []string{"0", "not-a-number"} {
		status, body = stack.jsonRequest(t, http.MethodGet, path+"?limit="+invalidLimit, nil, adminToken)
		if status != http.StatusBadRequest {
			t.Fatalf("credentials limit %q status = %d, want %d: %s", invalidLimit, status, http.StatusBadRequest, body)
		}
	}

	status, body = stack.jsonRequest(t, http.MethodGet, path+"?limit=4", nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("first credential metadata page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var firstPage userCredentialObservationPage
	decodeResponse(t, body, &firstPage)
	wantKinds := []string{"backup_codes", "passkeys", "password", "service", "totp", "totp_pending"}
	if len(firstPage.Items) != 4 || firstPage.NextCursor != "service" {
		t.Fatalf("first credential metadata page = %d items, cursor %q; want 4 items and kind cursor service", len(firstPage.Items), firstPage.NextCursor)
	}
	for index, item := range firstPage.Items {
		assertUserObservationMapFields(t, item, "kind", "created_at", "rotated_at", "must_change")
		var kind string
		decodeResponse(t, item["kind"], &kind)
		if kind != wantKinds[index] {
			t.Fatalf("first credential metadata item %d kind = %q, want %q", index, kind, wantKinds[index])
		}
		var mustChange bool
		decodeResponse(t, item["must_change"], &mustChange)
		if mustChange != (kind == "password") {
			t.Fatalf("credential %q must_change = %t", kind, mustChange)
		}
	}
	assertUserObservationNoSecrets(t, body, "observation-secret-hash", "token_hash", "payload")

	status, body = stack.jsonRequest(t, http.MethodGet, path+"?limit=4&cursor="+firstPage.NextCursor, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("second credential metadata page status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var secondPage userCredentialObservationPage
	decodeResponse(t, body, &secondPage)
	if len(secondPage.Items) != 2 || secondPage.NextCursor != "" {
		t.Fatalf("second credential metadata page = %d items, cursor %q; want 2 items and no cursor", len(secondPage.Items), secondPage.NextCursor)
	}
	for index, item := range secondPage.Items {
		assertUserObservationMapFields(t, item, "kind", "created_at", "rotated_at", "must_change")
		var kind string
		decodeResponse(t, item["kind"], &kind)
		if kind != wantKinds[index+4] {
			t.Fatalf("second credential metadata item %d kind = %q, want %q", index, kind, wantKinds[index+4])
		}
	}
	assertUserObservationNoSecrets(t, body, "observation-secret-hash", "token_hash", "payload")
}

func TestAdminUserSessionObservation(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	target := createUserObservationTestUser(t, stack, "session-observation-target")
	now := time.Now().UTC()
	clientMetaMarker := "private-client-meta-observation"
	familyIDMarker := "private-family-observation"
	activeID := insertUserObservationSession(t, stack, target.ID, store.Session{
		FamilyID: familyIDMarker,
		ClientMeta: json.RawMessage(`{"marker":"private-client-meta-observation"}`),
		CreatedAt: now.Add(-time.Minute), LastActiveAt: now, ExpiresAt: now.Add(time.Hour),
		FamilyNotAfter: now.Add(24 * time.Hour),
	})
	path := "/users/" + target.ID + "/sessions/" + activeID

	status, body := stack.jsonRequest(t, http.MethodGet, path, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("session detail without token status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("active session detail status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "id", "created_at", "last_active_at", "expires_at")
	var active struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	decodeResponse(t, body, &active)
	if active.ID != activeID || !active.ExpiresAt.After(now) {
		t.Fatalf("active session detail = %+v, want session %q with a future expiry", active, activeID)
	}
	assertUserObservationNoSecrets(t, body, clientMetaMarker, familyIDMarker, "client_meta", "family_not_after")

	status, body = stack.jsonRequest(t, http.MethodDelete, path, nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("revoke observed session = %d %q, want empty %d", status, body, http.StatusNoContent)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("revoked session detail status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "id", "created_at", "last_active_at", "expires_at", "revoked_at", "revoke_reason")
	var revoked struct {
		RevokedAt    *time.Time `json:"revoked_at"`
		RevokeReason *string    `json:"revoke_reason"`
	}
	decodeResponse(t, body, &revoked)
	if revoked.RevokedAt == nil || revoked.RevokeReason == nil || *revoked.RevokeReason != "admin_revoked" {
		t.Fatalf("revoked session metadata = %+v, want revoke time and admin_revoked reason", revoked)
	}
	assertUserObservationNoSecrets(t, body, clientMetaMarker, familyIDMarker, "client_meta", "family_not_after")

	expiredID := insertUserObservationSession(t, stack, target.ID, store.Session{
		FamilyID: familyIDMarker + "-expired",
		ClientMeta: json.RawMessage(`{"marker":"private-expired-client-meta"}`),
		CreatedAt: now.Add(-3 * time.Hour), LastActiveAt: now.Add(-2 * time.Hour),
		ExpiresAt: now.Add(-time.Hour), FamilyNotAfter: now.Add(-time.Minute),
	})
	expiredPath := "/users/" + target.ID + "/sessions/" + expiredID
	status, body = stack.jsonRequest(t, http.MethodGet, expiredPath, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("expired session detail status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "id", "created_at", "last_active_at", "expires_at")
	var expired struct {
		ID        string    `json:"id"`
		ExpiresAt time.Time `json:"expires_at"`
	}
	decodeResponse(t, body, &expired)
	if expired.ID != expiredID || !expired.ExpiresAt.Before(time.Now().UTC()) {
		t.Fatalf("expired session detail = %+v, want expired session %q", expired, expiredID)
	}
	assertUserObservationNoSecrets(t, body, "private-expired-client-meta", familyIDMarker+"-expired", "client_meta", "family_not_after")

	foreignUser := createUserObservationTestUser(t, stack, "session-observation-foreign-owner")
	foreignID := insertUserObservationSession(t, stack, foreignUser.ID, store.Session{
		FamilyID: "private-foreign-family",
		ClientMeta: json.RawMessage(`{"marker":"private-foreign-client-meta"}`),
		CreatedAt: now, LastActiveAt: now, ExpiresAt: now.Add(time.Hour), FamilyNotAfter: now.Add(24 * time.Hour),
	})
	status, foreignBody := stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/sessions/"+foreignID, nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("foreign owner's session detail status = %d, want %d: %s", status, http.StatusNotFound, foreignBody)
	}
	status, missingBody := stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/sessions/missing-session", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing session detail status = %d, want %d: %s", status, http.StatusNotFound, missingBody)
	}
	var foreignProblem, missingProblem struct {
		Detail string `json:"detail"`
	}
	decodeResponse(t, foreignBody, &foreignProblem)
	decodeResponse(t, missingBody, &missingProblem)
	if foreignProblem.Detail == "" || foreignProblem.Detail != missingProblem.Detail {
		t.Fatalf("foreign session not-found detail %q differs from missing session detail %q", foreignProblem.Detail, missingProblem.Detail)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/missing-observation-user/sessions/"+activeID, nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing user session detail status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
}

func TestAdminUserSessionObservationUsesExistingSessionPermission(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := createUserObservationTestUser(t, stack, "session-permission-target")
	now := time.Now().UTC()
	sessionID := insertUserObservationSession(t, stack, target.ID, store.Session{
		FamilyID: "permission-observation-family", CreatedAt: now, LastActiveAt: now,
		ExpiresAt: now.Add(time.Hour), FamilyNotAfter: now.Add(24 * time.Hour),
	})
	sessionPath := "/users/" + target.ID + "/sessions/" + sessionID

	usersOnly := seedPasswordUser(t, ctx, stack.database.pool, "session-permission-users-only", "UsersOnlyObservationPassword1")
	usersOnlyRole := createBaselineTestRole(t, stack, adminToken, "observation-users-only", "", []string{"iam:users:any"})
	addUserObservationRoleBinding(t, stack, adminToken, usersOnlyRole.ID, usersOnly.ID)
	usersOnlyToken := loginUser(t, stack, usersOnly.Username, "UsersOnlyObservationPassword1")
	status, body := stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/credentials", nil, usersOnlyToken)
	if status != http.StatusOK {
		t.Fatalf("users:any credential observation status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, sessionPath, nil, usersOnlyToken)
	if status != http.StatusForbidden {
		t.Fatalf("users:any session detail status = %d, want %d: %s", status, http.StatusForbidden, body)
	}

	sessionsOnly := seedPasswordUser(t, ctx, stack.database.pool, "session-permission-sessions-only", "SessionsOnlyObservationPassword1")
	sessionsOnlyRole := createBaselineTestRole(t, stack, adminToken, "observation-sessions-only", "", []string{"iam:sessions:any"})
	addUserObservationRoleBinding(t, stack, adminToken, sessionsOnlyRole.ID, sessionsOnly.ID)
	sessionsOnlyToken := loginUser(t, stack, sessionsOnly.Username, "SessionsOnlyObservationPassword1")
	status, body = stack.jsonRequest(t, http.MethodGet, sessionPath, nil, sessionsOnlyToken)
	if status != http.StatusOK {
		t.Fatalf("sessions:any session detail status = %d, want %d: %s", status, http.StatusOK, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+target.ID+"/credentials", nil, sessionsOnlyToken)
	if status != http.StatusForbidden {
		t.Fatalf("sessions:any credential observation status = %d, want %d: %s", status, http.StatusForbidden, body)
	}
}

func TestAdminUserInvitationObservation(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	invitationID := createUserObservationTestInvitation(t, stack, adminToken, "invitation-observation-resend", "invitation-observation-resend@example.test")
	path := "/users/" + invitationID + "/invitation"

	status, body := stack.jsonRequest(t, http.MethodGet, path, nil, "")
	if status != http.StatusUnauthorized {
		t.Fatalf("invitation metadata without token status = %d, want %d: %s", status, http.StatusUnauthorized, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("pending invitation metadata status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "user_status", "created_at", "expires_at")
	var initial userInvitationObservationResponse
	decodeResponse(t, body, &initial)
	if initial.UserStatus != "invited" || !initial.ExpiresAt.After(initial.CreatedAt) || initial.UsedAt != nil {
		t.Fatalf("initial invitation metadata = %+v, want invited with future expiry and no used_at", initial)
	}
	assertUserObservationNoSecrets(t, body, "token", "token_hash", "payload", "email")
	oldToken := invitationOutboxToken(t, stack, invitationID)

	status, body = stack.jsonRequest(t, http.MethodPost, "/invitations/"+invitationID+"/resend", nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("resend observation invitation = %d %q, want empty %d", status, body, http.StatusNoContent)
	}
	newToken := invitationOutboxToken(t, stack, invitationID)
	if newToken == oldToken {
		t.Fatal("resend did not rotate the invitation token")
	}
	status, body = stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("resent invitation metadata status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "user_status", "created_at", "expires_at")
	var latest userInvitationObservationResponse
	decodeResponse(t, body, &latest)
	if latest.UserStatus != "invited" || latest.CreatedAt.Before(initial.CreatedAt) || !latest.ExpiresAt.After(initial.ExpiresAt) || latest.UsedAt != nil {
		t.Fatalf("latest resent invitation metadata = %+v, want newer invited row with unused latest token", latest)
	}
	assertUserObservationNoSecrets(t, body, "token", "token_hash", "payload", "email", oldToken, newToken)

	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/invite/accept", map[string]string{
		"token": newToken, "password": "Observation-InvitePassword1",
	}, "")
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("accept observed invitation = %d %q, want empty %d", status, body, http.StatusNoContent)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, path, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("accepted invitation metadata status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "user_status", "created_at", "expires_at", "used_at")
	var accepted userInvitationObservationResponse
	decodeResponse(t, body, &accepted)
	if accepted.UserStatus != "active" || accepted.UsedAt == nil {
		t.Fatalf("accepted invitation metadata = %+v, want actual active status and persisted used_at", accepted)
	}
	assertUserObservationNoSecrets(t, body, "token", "token_hash", "payload", "email", newToken, "accepted", "delivery")

	directlyActivatedID := createUserObservationTestInvitation(t, stack, adminToken, "invitation-observation-activated", "invitation-observation-activated@example.test")
	status, body = stack.jsonRequest(t, http.MethodPatch, "/users/"+directlyActivatedID, map[string]string{"status": "active"}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("directly activate invited user = %d, want %d: %s", status, http.StatusOK, body)
	}
	directPath := "/users/" + directlyActivatedID + "/invitation"
	status, body = stack.jsonRequest(t, http.MethodGet, directPath, nil, adminToken)
	if status != http.StatusOK {
		t.Fatalf("directly activated invitation metadata status = %d, want %d: %s", status, http.StatusOK, body)
	}
	assertUserObservationJSONFields(t, body, "user_status", "created_at", "expires_at")
	var directlyActivated userInvitationObservationResponse
	decodeResponse(t, body, &directlyActivated)
	if directlyActivated.UserStatus != "active" || directlyActivated.UsedAt != nil {
		t.Fatalf("directly activated invitation metadata = %+v, want active user with an unused invite record", directlyActivated)
	}
	assertUserObservationNoSecrets(t, body, "accepted", "delivery", "token_hash", "payload", "email")

	cancelledID := createUserObservationTestInvitation(t, stack, adminToken, "invitation-observation-cancelled", "invitation-observation-cancelled@example.test")
	status, body = stack.jsonRequest(t, http.MethodDelete, "/invitations/"+cancelledID, nil, adminToken)
	if status != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("cancel observed invitation = %d %q, want empty %d", status, body, http.StatusNoContent)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+cancelledID+"/invitation", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("cancelled invitation metadata status = %d, want %d: %s", status, http.StatusNotFound, body)
	}

	userWithoutInvitation := createUserObservationTestUser(t, stack, "user-without-observation-invitation")
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/"+userWithoutInvitation.ID+"/invitation", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("user without invitation metadata status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
	status, body = stack.jsonRequest(t, http.MethodGet, "/users/missing-observation-user/invitation", nil, adminToken)
	if status != http.StatusNotFound {
		t.Fatalf("missing user invitation metadata status = %d, want %d: %s", status, http.StatusNotFound, body)
	}
}

func createUserObservationTestUser(t *testing.T, stack *integrationStack, username string) store.User {
	t.Helper()
	user, err := store.CreateUser(context.Background(), stack.database.pool, store.User{
		Username: username,
		Status:   "active",
	})
	if err != nil {
		t.Fatalf("create observation user %q: %v", username, err)
	}
	return user
}

func insertUserObservationSession(t *testing.T, stack *integrationStack, userID string, session store.Session) string {
	t.Helper()
	if session.ID == "" {
		session.ID = store.NewID()
	}
	session.UserID = userID
	if _, err := store.CreateSession(context.Background(), stack.database.pool, session); err != nil {
		t.Fatalf("create observation session for %s: %v", userID, err)
	}
	return session.ID
}

func createUserObservationTestInvitation(t *testing.T, stack *integrationStack, adminToken, username, email string) string {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/invitations", map[string]string{
		"email": email, "username": username,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create observation invitation %q = %d %s, want %d", username, status, body, http.StatusCreated)
	}
	var created struct {
		ID     string `json:"id"`
		Status string `json:"status"`
	}
	decodeResponse(t, body, &created)
	if created.ID == "" || created.Status != "invited" {
		t.Fatalf("created observation invitation = %+v, want invited user ID", created)
	}
	return created.ID
}

func addUserObservationRoleBinding(t *testing.T, stack *integrationStack, adminToken, roleID, userID string) {
	t.Helper()
	status, body := stack.jsonRequest(t, http.MethodPost, "/bindings", map[string]string{
		"role_id": roleID, "subject_kind": "user", "subject_id": userID,
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("bind observation role %s to user %s = %d %s, want %d", roleID, userID, status, body, http.StatusCreated)
	}
}

func assertUserObservationMapFields(t *testing.T, fields map[string]json.RawMessage, expected ...string) {
	t.Helper()
	if len(fields) != len(expected) {
		t.Fatalf("observation fields = %v, want exactly %v", fields, expected)
	}
	for _, name := range expected {
		if _, ok := fields[name]; !ok {
			t.Fatalf("observation fields = %v, missing %q", fields, name)
		}
	}
}

func assertUserObservationJSONFields(t *testing.T, body []byte, expected ...string) {
	t.Helper()
	var fields map[string]json.RawMessage
	decodeResponse(t, body, &fields)
	assertUserObservationMapFields(t, fields, expected...)
}

func assertUserObservationNoSecrets(t *testing.T, body []byte, forbidden ...string) {
	t.Helper()
	for _, value := range forbidden {
		if value != "" && strings.Contains(string(body), value) {
			t.Fatalf("observation response contains forbidden value %q: %s", value, body)
		}
	}
}
