package iam

import (
	"errors"
	"strings"
)

// PermissionSubscription is a closeable SDK event subscription shared by
// permission, key-rotation, and lifecycle handlers.
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

// SubscribeKeyRotations refreshes a verifier's JWKS cache on the iam.key.rotated
// NATS subject. An empty URL is a guarded no-op.
func (v *Verifier) SubscribeKeyRotations(natsURL string) (*PermissionSubscription, error) {
	if v == nil {
		return nil, errors.New("nil verifier")
	}
	if strings.TrimSpace(natsURL) == "" {
		return nil, nil
	}
	return subscribeKeyRotationsNATS(v, natsURL)
}

type permissionEvent struct {
	EventID int64    `json:"event_id"`
	Type    string   `json:"type"`
	UserIDs []string `json:"user_ids"`
	TeamID  string   `json:"team_id"`
	At      string   `json:"at"`
}

type LifecycleEventKind string

const (
	UserCreatedEventKind LifecycleEventKind = "user.created"
	UserUpdatedEventKind LifecycleEventKind = "user.updated"
	UserDeletedEventKind LifecycleEventKind = "user.deleted"
	TeamCreatedEventKind LifecycleEventKind = "team.created"
	TeamUpdatedEventKind LifecycleEventKind = "team.updated"

	UserCreatedEventSubject = "iam.user.created"
	UserUpdatedEventSubject = "iam.user.updated"
	UserDeletedEventSubject = "iam.user.deleted"
	TeamCreatedEventSubject = "iam.team.created"
	TeamUpdatedEventSubject = "iam.team.updated"
)

type UserCreatedEvent struct {
	EventID       int64              `json:"event_id"`
	Type          LifecycleEventKind `json:"type"`
	UserID        string             `json:"user_id"`
	ChangedFields []string           `json:"changed_fields"`
	At            string             `json:"at"`
}

type UserUpdatedEvent struct {
	EventID       int64              `json:"event_id"`
	Type          LifecycleEventKind `json:"type"`
	UserID        string             `json:"user_id"`
	ChangedFields []string           `json:"changed_fields"`
	At            string             `json:"at"`
}

type UserDeletedEvent struct {
	EventID int64              `json:"event_id"`
	Type    LifecycleEventKind `json:"type"`
	UserID  string             `json:"user_id"`
	At      string             `json:"at"`
}

type TeamCreatedEvent struct {
	EventID       int64              `json:"event_id"`
	Type          LifecycleEventKind `json:"type"`
	TeamID        string             `json:"team_id"`
	ChangedFields []string           `json:"changed_fields"`
	At            string             `json:"at"`
}

type TeamUpdatedEvent struct {
	EventID       int64              `json:"event_id"`
	Type          LifecycleEventKind `json:"type"`
	TeamID        string             `json:"team_id"`
	ChangedFields []string           `json:"changed_fields"`
	At            string             `json:"at"`
}

// SubscribeUserCreated registers a callback for user.created lifecycle events.
func SubscribeUserCreated(natsURL string, handler func(UserCreatedEvent)) (*PermissionSubscription, error) {
	return subscribeLifecycleEvent(natsURL, UserCreatedEventSubject, handler)
}

// SubscribeUserUpdated registers a callback for user.updated lifecycle events.
func SubscribeUserUpdated(natsURL string, handler func(UserUpdatedEvent)) (*PermissionSubscription, error) {
	return subscribeLifecycleEvent(natsURL, UserUpdatedEventSubject, handler)
}

// SubscribeUserDeleted registers a callback for user.deleted lifecycle events.
func SubscribeUserDeleted(natsURL string, handler func(UserDeletedEvent)) (*PermissionSubscription, error) {
	return subscribeLifecycleEvent(natsURL, UserDeletedEventSubject, handler)
}

// SubscribeTeamCreated registers a callback for team.created lifecycle events.
func SubscribeTeamCreated(natsURL string, handler func(TeamCreatedEvent)) (*PermissionSubscription, error) {
	return subscribeLifecycleEvent(natsURL, TeamCreatedEventSubject, handler)
}

// SubscribeTeamUpdated registers a callback for team.updated lifecycle events.
func SubscribeTeamUpdated(natsURL string, handler func(TeamUpdatedEvent)) (*PermissionSubscription, error) {
	return subscribeLifecycleEvent(natsURL, TeamUpdatedEventSubject, handler)
}

func subscribeLifecycleEvent[T any](natsURL, subject string, handler func(T)) (*PermissionSubscription, error) {
	if strings.TrimSpace(natsURL) == "" {
		return nil, nil
	}
	return subscribeLifecycleEventNATS(natsURL, subject, handler)
}
