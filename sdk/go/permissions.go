package iam

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultPermissionTTL = 2 * time.Minute
var errInvalidPermissionSnapshot = errors.New("invalid v2 permission snapshot")
var errPermissionSnapshotInvalidated = fmt.Errorf("%w: cache invalidated while request was in flight", errInvalidPermissionSnapshot)

// Grant is one effective permission, its optional ABAC condition, and its optional team scope.
type Grant struct {
	Key       string             `json:"key"`
	Condition *CompiledCondition `json:"condition,omitempty"`
	TeamID    *string            `json:"team_id,omitempty"`

	permission   Permission
	conditionErr error
}

// MarshalJSON preserves the cache-fill contract: condition is sent as its
// source string, not as the compiled VM program.
func (g Grant) MarshalJSON() ([]byte, error) {
	var condition *string
	if g.Condition != nil && strings.TrimSpace(g.Condition.Source) != "" {
		condition = &g.Condition.Source
	}
	return json.Marshal(struct {
		Key       string  `json:"key"`
		Condition *string `json:"condition,omitempty"`
		TeamID    *string `json:"team_id,omitempty"`
	}{Key: g.Key, Condition: condition, TeamID: g.TeamID})
}
// UnmarshalJSON validates and compiles one v2 grant while retaining its scope.
func (g *Grant) UnmarshalJSON(data []byte) error {
	if g == nil {
		return errors.New("nil grant")
	}
	*g = Grant{}
	var wire struct {
		Key       *string         `json:"key"`
		Condition json.RawMessage `json:"condition"`
		TeamID    json.RawMessage `json:"team_id"`
	}
	if err := decodeSingleJSON(bytes.NewReader(data), &wire); err != nil {
		return err
	}
	if wire.Key == nil {
		return errors.New("grant key is required")
	}
	permission, err := Parse(*wire.Key)
	if err != nil {
		return err
	}

	var source string
	if len(wire.Condition) != 0 {
		conditionJSON := bytes.TrimSpace(wire.Condition)
		if bytes.Equal(conditionJSON, []byte("null")) {
			return errors.New("grant condition must be a string")
		}
		if err := json.Unmarshal(conditionJSON, &source); err != nil {
			return fmt.Errorf("grant condition must be a string: %w", err)
		}
	}
	var teamID *string
	if len(wire.TeamID) != 0 {
		teamJSON := bytes.TrimSpace(wire.TeamID)
		if !bytes.Equal(teamJSON, []byte("null")) {
			var value string
			if err := json.Unmarshal(teamJSON, &value); err != nil {
				return fmt.Errorf("grant team_id must be a nonempty string or null: %w", err)
			}
			if value == "" {
				return errors.New("grant team_id must be a nonempty string or null")
			}
			teamID = &value
		}
	}

	g.Key = *wire.Key
	g.permission = permission
	g.TeamID = teamID
	if strings.TrimSpace(source) != "" {
		condition, err := CompileCondition(source)
		if err != nil {
			g.conditionErr = fmt.Errorf("compile grant condition: %w", err)
		} else {
			g.Condition = condition
		}
	}
	return nil
}
// PermissionEntry is the cache-fill response retained by PermissionsClient.
type PermissionEntry struct {
	UserID     string     `json:"user_id"`
	PermVer    int64      `json:"perm_ver"`
	Grants     []Grant    `json:"grants"`
	ValidUntil *time.Time `json:"valid_until,omitempty"`
}

// Permissions is an alias for PermissionEntry.
type Permissions = PermissionEntry

// CachedPermissions is an alias for PermissionEntry.
type CachedPermissions = PermissionEntry

// CheckResult is the response from the authoritative remote check endpoint.
type CheckResult struct {
	Allow   bool     `json:"allow"`
	Matched []string `json:"matched"`
	Reason  string   `json:"reason"`
}

type cachedPermissionEntry struct {
	entry     *PermissionEntry
	expiresAt time.Time
}

type permissionCall struct {
	done       chan struct{}
	entry      *PermissionEntry
	err        error
	clearEpoch uint64
	userEpoch  uint64
}

// PermissionsClient owns the local effective-permission cache and the remote
// authorization endpoints.
type PermissionsClient struct {
	base         string
	serviceToken string
	tokenSource  func() (string, error)
	httpClient   *http.Client
	ttl          time.Duration

	mu         sync.Mutex
	entries    map[string]cachedPermissionEntry
	inflight   map[string]*permissionCall
	clearEpoch uint64
	userEpochs map[string]uint64
}

// NewPermissionsClient constructs a permission cache with a two-minute TTL.
// Options may be SDK Option values; a string is accepted as a shorthand for
// the static service token, and a token-source function is accepted directly.
func NewPermissionsClient(base string, opts ...any) *PermissionsClient {
	client := &PermissionsClient{
		base:       strings.TrimRight(strings.TrimSpace(base), "/"),
		httpClient: http.DefaultClient,
		ttl:        defaultPermissionTTL,
		entries:    make(map[string]cachedPermissionEntry),
		inflight:   make(map[string]*permissionCall),
		userEpochs: make(map[string]uint64),
	}
	for _, rawOption := range opts {
		switch option := rawOption.(type) {
		case Option:
			if option != nil {
				option(client)
			}
		case string:
			client.serviceToken = strings.TrimSpace(option)
		case func() (string, error):
			client.tokenSource = option
		}
	}
	if client.httpClient == nil {
		client.httpClient = http.DefaultClient
	}
	if client.ttl < 0 {
		client.ttl = defaultPermissionTTL
	}
	return client
}

// Get returns the effective permission set for userID. Calls for one user are
// single-flight; callers for different users fetch independently.
func (p *PermissionsClient) Get(ctx context.Context, userID string, tokenPermVer int64) (*PermissionEntry, error) {
	if p == nil {
		return nil, errors.New("nil permissions client")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	userID = strings.TrimSpace(userID)
	if userID == "" {
		return nil, errors.New("user ID is empty")
	}

	p.mu.Lock()
	if p.entries == nil {
		p.entries = make(map[string]cachedPermissionEntry)
	}
	if p.inflight == nil {
		p.inflight = make(map[string]*permissionCall)
	}
	if p.userEpochs == nil {
		p.userEpochs = make(map[string]uint64)
	}
	now := time.Now()
	if cached, found := p.entries[userID]; found && now.Before(cached.expiresAt) && cached.entry != nil && cached.entry.PermVer == tokenPermVer {
		entry := clonePermissionEntry(cached.entry)
		p.mu.Unlock()
		return entry, nil
	}
	if call, running := p.inflight[userID]; running {
		p.mu.Unlock()
		select {
		case <-call.done:
			p.mu.Lock()
			entry, err := call.entry, call.err
			if p.clearEpoch != call.clearEpoch || p.userEpochs[userID] != call.userEpoch {
				entry, err = nil, errPermissionSnapshotInvalidated
			}
			p.mu.Unlock()
			return clonePermissionEntry(entry), err
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	call := &permissionCall{
		done:       make(chan struct{}),
		clearEpoch: p.clearEpoch,
		userEpoch:  p.userEpochs[userID],
	}
	p.inflight[userID] = call
	p.mu.Unlock()

	entry, err := p.fetch(ctx, userID)
	p.mu.Lock()
	if p.inflight[userID] == call {
		delete(p.inflight, userID)
	}
	if p.clearEpoch != call.clearEpoch || p.userEpochs[userID] != call.userEpoch {
		entry, err = nil, errPermissionSnapshotInvalidated
	}
	if err == nil && entry != nil {
		now := time.Now()
		expiresAt := now.Add(p.ttl)
		if entry.ValidUntil != nil && entry.ValidUntil.Before(expiresAt) {
			expiresAt = *entry.ValidUntil
		}
		p.entries[userID] = cachedPermissionEntry{
			entry:     clonePermissionEntry(entry),
			expiresAt: expiresAt,
		}
	}
	call.entry = clonePermissionEntry(entry)
	call.err = err
	close(call.done)
	p.mu.Unlock()
	return entry, err
}

// Invalidate drops cached entries and in-flight snapshots for the supplied user IDs.
// Empty IDs are ignored so malformed events cannot evict an unrelated entry.
func (p *PermissionsClient) Invalidate(userIDs ...string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.userEpochs == nil {
		p.userEpochs = make(map[string]uint64)
	}
	for _, userID := range userIDs {
		if userID = strings.TrimSpace(userID); userID != "" {
			p.userEpochs[userID]++
			delete(p.entries, userID)
			delete(p.inflight, userID)
		}
	}
}

// InvalidatePermissions is an explicit alias for Invalidate.
func (p *PermissionsClient) InvalidatePermissions(userIDs ...string) {
	p.Invalidate(userIDs...)
}

// Clear removes all cached permission entries and invalidates in-flight snapshots.
func (p *PermissionsClient) Clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.clearEpoch++
	p.entries = make(map[string]cachedPermissionEntry)
	p.inflight = make(map[string]*permissionCall)
	p.userEpochs = make(map[string]uint64)
	p.mu.Unlock()
}

func (p *PermissionsClient) fetch(ctx context.Context, userID string) (*PermissionEntry, error) {
	if strings.TrimSpace(p.base) == "" {
		return nil, errors.New("authorization base URL is empty")
	}
	token, err := p.serviceBearer()
	if err != nil {
		return nil, err
	}
	endpoint := strings.TrimRight(p.base, "/") + "/authz/permissions/" + url.PathEscape(userID) + "?version=2"
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create permissions request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	httpClient := p.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch permissions: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode == http.StatusBadRequest {
		return nil, fmt.Errorf("%w: unsupported snapshot response (HTTP %s)", errInvalidPermissionSnapshot, response.Status)
	}
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch permissions: unexpected HTTP status %s", response.Status)
	}
	return decodePermissionSnapshot(response.Body, userID)
}

func decodePermissionSnapshot(reader io.Reader, userID string) (*PermissionEntry, error) {
	var payload struct {
		Version    *int            `json:"version"`
		UserID     *string         `json:"user_id"`
		PermVer    *int64          `json:"perm_ver"`
		Grants     json.RawMessage `json:"grants"`
		ValidUntil json.RawMessage `json:"valid_until"`
	}
	if err := decodeSingleJSON(reader, &payload); err != nil {
		return nil, fmt.Errorf("%w: decode permissions: %v", errInvalidPermissionSnapshot, err)
	}
	if payload.Version == nil || *payload.Version != 2 {
		return nil, fmt.Errorf("%w: version must be 2", errInvalidPermissionSnapshot)
	}
	if payload.UserID == nil || *payload.UserID != userID {
		return nil, fmt.Errorf("%w: response user_id must match %q", errInvalidPermissionSnapshot, userID)
	}
	if payload.PermVer == nil || *payload.PermVer < 0 {
		return nil, fmt.Errorf("%w: perm_ver must be a non-negative integer", errInvalidPermissionSnapshot)
	}
	grantsJSON := bytes.TrimSpace(payload.Grants)
	if len(grantsJSON) == 0 || grantsJSON[0] != '[' {
		return nil, fmt.Errorf("%w: grants must be an array", errInvalidPermissionSnapshot)
	}
	var wireGrants []json.RawMessage
	if err := json.Unmarshal(grantsJSON, &wireGrants); err != nil {
		return nil, fmt.Errorf("%w: decode grants: %v", errInvalidPermissionSnapshot, err)
	}
	entry := &PermissionEntry{UserID: *payload.UserID, PermVer: *payload.PermVer, Grants: make([]Grant, 0, len(wireGrants))}
	if len(payload.ValidUntil) != 0 {
		deadlineJSON := bytes.TrimSpace(payload.ValidUntil)
		if bytes.Equal(deadlineJSON, []byte("null")) {
			return nil, fmt.Errorf("%w: valid_until must be an RFC3339 string", errInvalidPermissionSnapshot)
		}
		var value string
		if err := json.Unmarshal(deadlineJSON, &value); err != nil {
			return nil, fmt.Errorf("%w: valid_until must be an RFC3339 string: %v", errInvalidPermissionSnapshot, err)
		}
		deadline, err := time.Parse(time.RFC3339, value)
		if err != nil {
			return nil, fmt.Errorf("%w: valid_until must be an RFC3339 string: %v", errInvalidPermissionSnapshot, err)
		}
		if !time.Now().Before(deadline) {
			return nil, fmt.Errorf("%w: valid_until is expired", errInvalidPermissionSnapshot)
		}
		entry.ValidUntil = &deadline
	}
	for index, rawGrant := range wireGrants {
		var grant Grant
		if err := decodeSingleJSON(bytes.NewReader(rawGrant), &grant); err != nil {
			return nil, fmt.Errorf("%w: decode grant %d: %v", errInvalidPermissionSnapshot, index, err)
		}
		entry.Grants = append(entry.Grants, grant)
	}
	return entry, nil
}

func decodeSingleJSON(reader io.Reader, target any) error {
	decoder := json.NewDecoder(reader)
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return errors.New("multiple JSON values")
		}
		return err
	}
	return nil
}

func (p *PermissionsClient) serviceBearer() (string, error) {
	if p.tokenSource != nil {
		token, err := p.tokenSource()
		if err != nil {
			return "", fmt.Errorf("get service token: %w", err)
		}
		if token = strings.TrimSpace(token); token == "" {
			return "", errors.New("service token is empty")
		}
		return token, nil
	}
	if token := strings.TrimSpace(p.serviceToken); token != "" {
		return token, nil
	}
	return "", errors.New("service token is not configured")
}

func (p *PermissionsClient) Check(ctx context.Context, subject, permission string, resource Resource) (CheckResult, error) {
	if p == nil {
		return CheckResult{}, errors.New("nil permissions client")
	}
	if ctx == nil {
		ctx = context.Background()
	}
	if strings.TrimSpace(subject) == "" {
		return CheckResult{}, errors.New("subject is empty")
	}
	if _, err := Parse(permission); err != nil {
		return CheckResult{}, err
	}
	token, err := p.serviceBearer()
	if err != nil {
		return CheckResult{}, err
	}
	httpClient := p.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	endpoint := strings.TrimRight(p.base, "/") + "/authz/check"
	payload := struct {
		Subject    string `json:"subject"`
		Permission string `json:"permission"`
		Context    struct {
			Resource Resource `json:"resource"`
		} `json:"context"`
	}{Subject: subject, Permission: permission}
	payload.Context.Resource = resource
	body, err := json.Marshal(payload)
	if err != nil {
		return CheckResult{}, fmt.Errorf("encode authorization request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, strings.NewReader(string(body)))
	if err != nil {
		return CheckResult{}, fmt.Errorf("create authorization request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	request.Header.Set("Content-Type", "application/json")
	response, err := httpClient.Do(request)
	if err != nil {
		return CheckResult{}, fmt.Errorf("remote authorization check: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return CheckResult{}, fmt.Errorf("remote authorization check: unexpected HTTP status %s", response.Status)
	}
	var result CheckResult
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return CheckResult{}, fmt.Errorf("decode authorization response: %w", err)
	}
	if result.Reason == "" {
		if result.Allow {
			result.Reason = "permission granted"
		} else {
			result.Reason = "permission denied"
		}
	}
	return result, nil
}

func clonePermissionEntry(entry *PermissionEntry) *PermissionEntry {
	if entry == nil {
		return nil
	}
	clone := &PermissionEntry{
		UserID:     entry.UserID,
		PermVer:    entry.PermVer,
		Grants:     make([]Grant, len(entry.Grants)),
		ValidUntil: entry.ValidUntil,
	}
	if entry.ValidUntil != nil {
		deadline := *entry.ValidUntil
		clone.ValidUntil = &deadline
	}
	for index, grant := range entry.Grants {
		clone.Grants[index] = grant
		if grant.TeamID != nil {
			teamID := *grant.TeamID
			clone.Grants[index].TeamID = &teamID
		}
	}
	return clone
}
