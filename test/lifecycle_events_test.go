package test

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"
)

func TestAdminUserCreationEnqueuesLifecycleEvent(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username":     "lifecycle-event-user",
		"display_name": "Lifecycle Event User",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &created)
	if created.ID == "" {
		t.Fatal("created user has no ID")
	}

	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload
		FROM outbox
		WHERE topic = 'user.created' AND payload->>'user_id' = $1
		ORDER BY id DESC
		LIMIT 1`, created.ID).Scan(&payload); err != nil {
		t.Fatalf("read user.created outbox row: %v", err)
	}
	var event struct {
		UserID        string   `json:"user_id"`
		ChangedFields []string `json:"changed_fields"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode user.created payload: %v", err)
	}
	if event.UserID != created.ID {
		t.Fatalf("user.created user_id = %q, want %q", event.UserID, created.ID)
	}
	wantFields := []string{"username", "email", "display_name", "status"}
	if len(event.ChangedFields) != len(wantFields) {
		t.Fatalf("user.created changed_fields = %v, want %v", event.ChangedFields, wantFields)
	}
	for index, field := range wantFields {
		if event.ChangedFields[index] != field {
			t.Fatalf("user.created changed_fields = %v, want %v", event.ChangedFields, wantFields)
		}
	}
}

func TestAdminUserNoOpUpdateOmitsLifecycleEvent(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username":     "lifecycle-noop-user",
		"display_name": "Before",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &created)

	status, body = stack.jsonRequest(t, http.MethodPatch, "/users/"+created.ID, map[string]string{
		"display_name": "After",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("change display name status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload FROM outbox
		WHERE topic = 'user.updated' AND payload->>'user_id' = $1`, created.ID).Scan(&payload); err != nil {
		t.Fatalf("read user.updated outbox row: %v", err)
	}
	var event struct {
		ChangedFields []string `json:"changed_fields"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode user.updated payload: %v", err)
	}
	if len(event.ChangedFields) != 1 || event.ChangedFields[0] != "display_name" {
		t.Fatalf("user.updated changed_fields = %v, want [display_name]", event.ChangedFields)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/users/"+created.ID, map[string]string{
		"display_name": "After",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("no-op display name patch status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var eventCount int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM outbox
		WHERE topic = 'user.updated' AND payload->>'user_id' = $1`, created.ID).Scan(&eventCount); err != nil {
		t.Fatalf("count user.updated outbox rows: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("user.updated event count after no-op patch = %d, want 1", eventCount)
	}
}

func TestAdminTeamNoOpUpdateOmitsLifecycleEvent(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/teams", map[string]string{
		"slug": "lifecycle-noop-team",
		"name": "Before",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create team status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &created)

	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+created.ID, map[string]string{
		"name": "After",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("change team name status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload FROM outbox
		WHERE topic = 'team.updated' AND payload->>'team_id' = $1`, created.ID).Scan(&payload); err != nil {
		t.Fatalf("read team.updated outbox row: %v", err)
	}
	var event struct {
		ChangedFields []string `json:"changed_fields"`
	}
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode team.updated payload: %v", err)
	}
	if len(event.ChangedFields) != 1 || event.ChangedFields[0] != "name" {
		t.Fatalf("team.updated changed_fields = %v, want [name]", event.ChangedFields)
	}

	status, body = stack.jsonRequest(t, http.MethodPatch, "/teams/"+created.ID, map[string]string{
		"name": "After",
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("no-op team name patch status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var eventCount int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM outbox
		WHERE topic = 'team.updated' AND payload->>'team_id' = $1`, created.ID).Scan(&eventCount); err != nil {
		t.Fatalf("count team.updated outbox rows: %v", err)
	}
	if eventCount != 1 {
		t.Fatalf("team.updated event count after no-op patch = %d, want 1", eventCount)
	}
}

func TestAdminUserDeletionEnqueuesLifecycleEventWithoutChangedFields(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/users", map[string]string{
		"username": "lifecycle-deleted-user",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create user status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var created struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &created)
	status, body = stack.jsonRequest(t, http.MethodDelete, "/users/"+created.ID, nil, adminToken)
	if status != http.StatusNoContent {
		t.Fatalf("delete user status = %d, want %d: %s", status, http.StatusNoContent, body)
	}

	var payload []byte
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT payload FROM outbox
		WHERE topic = 'user.deleted' AND payload->>'user_id' = $1`, created.ID).Scan(&payload); err != nil {
		t.Fatalf("read user.deleted outbox row: %v", err)
	}
	var event map[string]json.RawMessage
	if err := json.Unmarshal(payload, &event); err != nil {
		t.Fatalf("decode user.deleted payload: %v", err)
	}
	var userID string
	if err := json.Unmarshal(event["user_id"], &userID); err != nil || userID != created.ID {
		t.Fatalf("user.deleted user_id = %q, %v; want %q", userID, err, created.ID)
	}
	if len(event) != 1 {
		t.Fatalf("user.deleted payload fields = %v, want only user_id", event)
	}
}
