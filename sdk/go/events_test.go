package iam

import (
	"encoding/json"
	"testing"
)

func TestPermissionEventDecodesRelayEventID(t *testing.T) {
	const payload = `{"event_id":1700000000000000017,"type":"perm.changed","user_ids":["usr_1"],"at":"2026-09-30T00:00:00Z"}`

	var event permissionEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatalf("decode relay event: %v", err)
	}
	if event.EventID != 1700000000000000017 {
		t.Fatalf("event_id = %d, want 1700000000000000017", event.EventID)
	}
	if event.Type != "perm.changed" || len(event.UserIDs) != 1 || event.UserIDs[0] != "usr_1" {
		t.Fatalf("decoded permission event = %+v", event)
	}
}

func TestUserDeletedEventDecodesRelayPayloadWithoutChangedFields(t *testing.T) {
	const payload = `{"event_id":23,"type":"user.deleted","user_id":"usr_1","at":"2026-09-30T00:00:00Z"}`

	var event UserDeletedEvent
	if err := json.Unmarshal([]byte(payload), &event); err != nil {
		t.Fatalf("decode user.deleted event: %v", err)
	}
	if event.EventID != 23 || event.Type != UserDeletedEventKind || event.UserID != "usr_1" {
		t.Fatalf("decoded user.deleted event = %+v", event)
	}
}
