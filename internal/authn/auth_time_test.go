package authn

import (
	"context"
	"testing"
	"time"

	"teamusers/internal/config"
	"teamusers/internal/store"
)

func TestIssuePairRequiresUserAuthTime(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	service := &Service{
		cfg: config.Config{SessionFamilyTTL: time.Hour},
		now: func() time.Time { return now },
	}
	_, err := service.issuePair(context.Background(), nil, store.User{ID: "usr_test"}, "user", "", time.Time{}, sessionMetadata{Kind: "user"})
	if err == nil || err.Error() != "user authentication time is required" {
		t.Fatalf("issuePair() error = %v, want missing user auth_time error", err)
	}
}

func TestSessionMetadataFromTreatsMalformedDataAsMissing(t *testing.T) {
	metadata := sessionMetadataFrom(store.Session{ClientMeta: []byte(`{"kind":"user","auth_time":`)} )
	if metadata.Kind != "" || metadata.AuthTime != 0 || len(metadata.AMR) != 0 {
		t.Fatalf("sessionMetadataFrom() = %+v, want empty metadata", metadata)
	}
}
