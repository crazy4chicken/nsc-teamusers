package store

import (
	"encoding/json"
	"time"
)

// User mirrors the users table.
type User struct {
	ID              string     `json:"id"`
	Username        string     `json:"username"`
	Email           *string    `json:"email,omitempty"`
	DisplayName     string     `json:"display_name"`
	Status          string     `json:"status"`
	PermVer         int64      `json:"perm_ver"`
	FailedLogins    int        `json:"failed_logins"`
	LockedUntil     *time.Time `json:"locked_until,omitempty"`
	EmailVerifiedAt *time.Time `json:"email_verified_at,omitempty"`
	ApprovedAt      *time.Time `json:"approved_at,omitempty"`
	ApprovedBy      *string    `json:"approved_by,omitempty"`
	CreatedAt       time.Time  `json:"created_at"`
	UpdatedAt       time.Time  `json:"updated_at"`
}

// Credential mirrors the credentials table.
type Credential struct {
	UserID    string     `json:"user_id"`
	Kind      string     `json:"kind"`
	Hash      string     `json:"hash"`
	CreatedAt time.Time  `json:"created_at"`
	RotatedAt *time.Time `json:"rotated_at,omitempty"`
}

// Team mirrors the teams table.
type Team struct {
	ID        string    `json:"id"`
	Slug      string    `json:"slug"`
	Name      string    `json:"name"`
	Status    string    `json:"status"`
	CreatedAt time.Time `json:"created_at"`
}

// Group mirrors the groups table.
type Group struct {
	ID     string `json:"id"`
	TeamID string `json:"team_id"`
	Name   string `json:"name"`
}

// Membership mirrors the memberships table.
type Membership struct {
	TeamID    string     `json:"team_id"`
	GroupID   string     `json:"group_id"`
	UserID    string     `json:"user_id"`
	ExpiresAt *time.Time `json:"expires_at,omitempty"`
}

// Permission mirrors the permissions table.
type Permission struct {
	Key          string    `json:"key"`
	Description  string    `json:"description"`
	RegisteredBy string    `json:"registered_by"`
	CreatedAt    time.Time `json:"created_at"`
}

// Role mirrors the roles table. A nil TeamID denotes platform scope.
type Role struct {
	ID     string  `json:"id"`
	TeamID *string `json:"team_id,omitempty"`
	Name   string  `json:"name"`
}

// RoleBinding mirrors the role_bindings table.
type RoleBinding struct {
	ID          string     `json:"id"`
	TeamID      *string    `json:"team_id,omitempty"`
	RoleID      string     `json:"role_id"`
	SubjectKind string     `json:"subject_kind"`
	SubjectID   string     `json:"subject_id"`
	Condition   *string    `json:"condition,omitempty"`
	ExpiresAt   *time.Time `json:"expires_at,omitempty"`
}

// Session mirrors the sessions table.
type Session struct {
	ID             string          `json:"id"`
	UserID         string          `json:"user_id"`
	FamilyID       string          `json:"family_id"`
	ClientMeta     json.RawMessage `json:"client_meta"`
	CreatedAt      time.Time       `json:"created_at"`
	ExpiresAt      time.Time       `json:"expires_at"`
	FamilyNotAfter time.Time       `json:"family_not_after"`
	RevokedAt      *time.Time      `json:"revoked_at,omitempty"`
	RevokeReason   *string         `json:"revoke_reason,omitempty"`
}

// AuditEntry mirrors an append-only audit_log row.
type AuditEntry struct {
	ID        int64           `json:"id"`
	TeamID    *string         `json:"team_id,omitempty"`
	ActorID   *string         `json:"actor_id,omitempty"`
	Action    string          `json:"action"`
	Target    string          `json:"target"`
	Diff      json.RawMessage `json:"diff"`
	RequestID *string         `json:"request_id,omitempty"`
	At        time.Time       `json:"at"`
}

// OutboxEvent mirrors an outbox row.
type OutboxEvent struct {
	ID          int64           `json:"id"`
	Topic       string          `json:"topic"`
	Payload     json.RawMessage `json:"payload"`
	PublishedAt *time.Time      `json:"published_at,omitempty"`
}
