package store

import (
	"reflect"
	"testing"
	"time"
)

func TestChangedUserLifecycleFieldsIncludesVerificationAndApproval(t *testing.T) {
	beforeEmail := "before@example.test"
	afterEmail := "after@example.test"
	approvedBy := "admin-user"
	verifiedAt := time.Date(2026, time.September, 30, 12, 0, 0, 0, time.UTC)
	approvedAt := verifiedAt.Add(time.Minute)
	before := User{
		Username: "lifecycle-user", Email: &beforeEmail, DisplayName: "Before", Status: "pending",
	}
	after := before
	after.Email = &afterEmail
	after.DisplayName = "After"
	after.Status = "active"
	after.EmailVerifiedAt = &verifiedAt
	after.ApprovedAt = &approvedAt
	after.ApprovedBy = &approvedBy

	got := changedUserLifecycleFields(before, after)
	want := []string{"email", "display_name", "status", "email_verified_at", "approved_at", "approved_by"}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("changed lifecycle fields = %v, want %v", got, want)
	}
	if got := changedUserLifecycleFields(after, after); len(got) != 0 {
		t.Fatalf("unchanged lifecycle fields = %v, want none", got)
	}
}
