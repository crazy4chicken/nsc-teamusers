package events

import "testing"

func TestLifecycleTopicsMapToJetStreamSubjects(t *testing.T) {
	tests := []struct {
		topic   string
		subject string
	}{
		{topic: "user.created", subject: "iam.user.created"},
		{topic: "user.updated", subject: "iam.user.updated"},
		{topic: "user.deleted", subject: "iam.user.deleted"},
		{topic: "team.created", subject: "iam.team.created"},
		{topic: "team.updated", subject: "iam.team.updated"},
	}
	for _, test := range tests {
		if got := natsSubjects[test.topic]; got != test.subject {
			t.Errorf("natsSubjects[%q] = %q, want %q", test.topic, got, test.subject)
		}
	}
}
