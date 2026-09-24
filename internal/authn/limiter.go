package authn

import (
	"strings"
	"sync"
	"time"
)

const (
	loginRatePerMinute = 5
	loginBurst         = 5
	ipRatePerMinute    = 30
	ipBurst            = 30
	limiterMaxKeys     = 10000
	limiterBucketTTL   = 2 * time.Minute
)

type loginLimiter struct {
	mu      sync.Mutex
	buckets map[string]loginBucket
}

type loginBucket struct {
	tokens float64
	at     time.Time
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{buckets: make(map[string]loginBucket)}
}

// allow enforces both the per-IP/username and coarse per-IP login limits.
func (l *loginLimiter) allow(ip, username string, now time.Time) bool {
	userKey := "user\x00" + ip + "\x00" + strings.ToLower(strings.TrimSpace(username))
	ipKey := "ip\x00" + ip
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	if !l.consumeLocked(userKey, loginRatePerMinute, loginBurst, now) {
		return false
	}
	return l.consumeLocked(ipKey, ipRatePerMinute, ipBurst, now)
}

// allowIP enforces the coarse per-IP limit for endpoints without a username.
func (l *loginLimiter) allowIP(ip string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.sweepLocked(now)
	return l.consumeLocked("ip\x00"+ip, ipRatePerMinute, ipBurst, now)
}

func (l *loginLimiter) consumeLocked(key string, ratePerMinute, burst int, now time.Time) bool {
	bucket, ok := l.buckets[key]
	if !ok {
		if len(l.buckets) >= limiterMaxKeys {
			if !l.evictExpiredLocked(now) {
				return false
			}
		}
		bucket = loginBucket{tokens: float64(burst), at: now}
	}
	elapsed := now.Sub(bucket.at).Seconds()
	if elapsed > 0 {
		bucket.tokens += elapsed * (float64(ratePerMinute) / 60)
		if bucket.tokens > float64(burst) {
			bucket.tokens = float64(burst)
		}
		bucket.at = now
	}
	if bucket.tokens < 1 {
		l.buckets[key] = bucket
		return false
	}
	bucket.tokens--
	l.buckets[key] = bucket
	return true
}

func (l *loginLimiter) sweepLocked(now time.Time) {
	for key, bucket := range l.buckets {
		if now.Sub(bucket.at) >= limiterBucketTTL {
			delete(l.buckets, key)
		}
	}
}

func (l *loginLimiter) evictExpiredLocked(now time.Time) bool {
	var oldestKey string
	var oldest time.Time
	for key, bucket := range l.buckets {
		if now.Sub(bucket.at) < limiterBucketTTL {
			continue
		}
		if oldestKey == "" || bucket.at.Before(oldest) {
			oldestKey, oldest = key, bucket.at
		}
	}
	if oldestKey == "" {
		return false
	}
	delete(l.buckets, oldestKey)
	return true
}
