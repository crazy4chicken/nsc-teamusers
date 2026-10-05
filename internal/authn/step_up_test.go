package authn

import (
	"testing"

	"teamusers/internal/httpapi"
)

func TestStepUpSubjectEligibility(t *testing.T) {
	for _, testCase := range []struct {
		name    string
		subject httpapi.Subject
		want    bool
	}{
		{name: "user", subject: httpapi.Subject{UserID: "user-1", Kind: "user"}, want: true},
		{name: "service", subject: httpapi.Subject{UserID: "service-1", Kind: "service"}},
		{name: "impersonated user", subject: httpapi.Subject{UserID: "user-1", Kind: "user", Impersonated: true, ActorID: "admin-1"}},
		{name: "actor claim", subject: httpapi.Subject{UserID: "user-1", Kind: "user", ActorID: "admin-1"}},
		{name: "missing user", subject: httpapi.Subject{Kind: "user"}},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			if got := stepUpSubjectEligible(testCase.subject); got != testCase.want {
				t.Fatalf("stepUpSubjectEligible(%+v) = %t, want %t", testCase.subject, got, testCase.want)
			}
		})
	}
}
