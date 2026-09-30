package authz

import (
	"testing"
	"time"
)

func TestAuthTimeFreshBoundaries(t *testing.T) {
	now := time.Unix(2_000_000_000, 0)
	tests := []struct {
		name          string
		authTime      int64
		maxAgeSeconds int64
		want          bool
	}{
		{name: "missing auth time", authTime: 0, maxAgeSeconds: 60, want: false},
		{name: "negative max age", authTime: now.Unix(), maxAgeSeconds: -1, want: false},
		{name: "inclusive max age boundary", authTime: now.Unix() - 60, maxAgeSeconds: 60, want: true},
		{name: "older than max age", authTime: now.Unix() - 61, maxAgeSeconds: 60, want: false},
		{name: "future within skew boundary", authTime: now.Unix() + 30, maxAgeSeconds: 60, want: true},
		{name: "future beyond skew", authTime: now.Unix() + 31, maxAgeSeconds: 60, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := authTimeFresh(tt.authTime, tt.maxAgeSeconds, now); got != tt.want {
				t.Fatalf("authTimeFresh(%d, %d, %s) = %v, want %v", tt.authTime, tt.maxAgeSeconds, now, got, tt.want)
			}
		})
	}
}
