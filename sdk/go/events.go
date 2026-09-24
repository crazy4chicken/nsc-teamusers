package iam

import (
	"errors"
	"strings"
)

// PermissionSubscription represents an optional NATS permission invalidation
// subscription. Close is safe to call more than once.
type PermissionSubscription struct {
	close func() error
}

// Close releases the underlying event subscription.
func (s *PermissionSubscription) Close() error {
	if s == nil || s.close == nil {
		return nil
	}
	close := s.close
	s.close = nil
	return close()
}

// SubscribePermissions subscribes to permission-affecting NATS events when
// the SDK is built with the nats tag. An empty URL is a guarded no-op.
func (p *PermissionsClient) SubscribePermissions(natsURL string, handler func(userIDs []string)) (*PermissionSubscription, error) {
	if p == nil {
		return nil, errors.New("nil permissions client")
	}
	if strings.TrimSpace(natsURL) == "" {
		return nil, nil
	}
	return subscribePermissionsNATS(p, natsURL, handler)
}

// SubscribePermissions delegates to the configured permission cache.
func (c *Client) SubscribePermissions(natsURL string, handler func(userIDs []string)) (*PermissionSubscription, error) {
	if c == nil || c.Permissions == nil {
		return nil, errors.New("permission client is unavailable")
	}
	return c.Permissions.SubscribePermissions(natsURL, handler)
}
