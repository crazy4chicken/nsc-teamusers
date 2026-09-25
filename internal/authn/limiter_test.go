package authn

import (
	"strconv"
	"testing"
	"time"
)

func TestLoginLimiterRefillsTokens(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for range loginBurst {
		if !limiter.allow("192.0.2.1", "alice", now) {
			t.Fatal("login limiter rejected a burst token")
		}
	}
	if limiter.allow("192.0.2.1", "alice", now) {
		t.Fatal("login limiter allowed a request after the burst was exhausted")
	}
	if !limiter.allow("192.0.2.1", "alice", now.Add(12*time.Second)) {
		t.Fatal("login limiter did not refill one token after elapsed time")
	}
}

func TestLoginLimiterRejectsLiveKeyOverflowAndEvictsExpiredKeys(t *testing.T) {
	limiter := newLoginLimiter()
	now := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	for index := range limiterMaxKeys {
		if !limiter.allowIP("198.51.100."+strconv.Itoa(index), now) {
			t.Fatalf("limiter rejected initial key %d", index)
		}
	}
	if limiter.allowIP("new-overflow", now) {
		t.Fatal("limiter allowed a new live key after reaching the key cap")
	}
	limiter.mu.Lock()
	limiter.buckets["ip\x00198.51.100.0"] = loginBucket{tokens: 1, at: now.Add(-limiterBucketTTL)}
	limiter.mu.Unlock()
	if !limiter.allowIP("new-overflow", now) {
		t.Fatal("limiter did not evict an expired key to admit a new key")
	}
}
