package iam

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const defaultPermissionTTL = 2 * time.Minute

// Grant is one effective permission and its optional ABAC condition.
type Grant struct {
	Key       string             `json:"key"`
	Condition *CompiledCondition `json:"condition,omitempty"`

	permission Permission
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
	}{Key: g.Key, Condition: condition})
}

// UnmarshalJSON compiles the server's condition source while retaining the
// original key string for callers.
func (g *Grant) UnmarshalJSON(data []byte) error {
	if g == nil {
		return errors.New("nil grant")
	}
	var wire struct {
		Key       string  `json:"key"`
		Condition *string `json:"condition"`
	}
	if err := json.Unmarshal(data, &wire); err != nil {
		return err
	}
	permission, err := Parse(wire.Key)
	if err != nil {
		return err
	}
	g.Key = wire.Key
	g.permission = permission
	g.Condition = nil
	if wire.Condition != nil && strings.TrimSpace(*wire.Condition) != "" {
		condition, err := CompileCondition(*wire.Condition)
		if err != nil {
			return err
		}
		g.Condition = condition
	}
	return nil
}

// PermissionEntry is the cache-fill response retained by PermissionsClient.
type PermissionEntry struct {
	UserID  string  `json:"user_id"`
	PermVer int64   `json:"perm_ver"`
	Grants  []Grant `json:"grants"`
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
	done  chan struct{}
	entry *PermissionEntry
	err   error
}

// PermissionsClient owns the local effective-permission cache and the remote
// authorization endpoints.
type PermissionsClient struct {
	base         string
	serviceToken string
	tokenSource  func() (string, error)
	httpClient   *http.Client
	ttl          time.Duration

	mu       sync.Mutex
	entries  map[string]cachedPermissionEntry
	inflight map[string]*permissionCall
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
	p.mu.Unlock()

	for {
		now := time.Now()
		p.mu.Lock()
		cached, found := p.entries[userID]
		if found && now.Before(cached.expiresAt) && cached.entry != nil && cached.entry.PermVer == tokenPermVer {
			entry := clonePermissionEntry(cached.entry)
			p.mu.Unlock()
			return entry, nil
		}
		if call, running := p.inflight[userID]; running {
			p.mu.Unlock()
			select {
			case <-call.done:
				return clonePermissionEntry(call.entry), call.err
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}
		call := &permissionCall{done: make(chan struct{})}
		p.inflight[userID] = call
		p.mu.Unlock()

		entry, err := p.fetch(ctx, userID)
		p.mu.Lock()
		delete(p.inflight, userID)
		if err == nil && entry != nil {
			p.entries[userID] = cachedPermissionEntry{
				entry:     clonePermissionEntry(entry),
				expiresAt: time.Now().Add(p.ttl),
			}
		}
		call.entry = clonePermissionEntry(entry)
		call.err = err
		close(call.done)
		p.mu.Unlock()
		return entry, err
	}
}

// Invalidate drops cached entries for the supplied user IDs. Empty IDs are
// ignored so malformed events cannot evict an unrelated entry.
func (p *PermissionsClient) Invalidate(userIDs ...string) {
	if p == nil {
		return
	}
	p.mu.Lock()
	defer p.mu.Unlock()
	for _, userID := range userIDs {
		if userID = strings.TrimSpace(userID); userID != "" {
			delete(p.entries, userID)
		}
	}
}

// InvalidatePermissions is an explicit alias for Invalidate.
func (p *PermissionsClient) InvalidatePermissions(userIDs ...string) {
	p.Invalidate(userIDs...)
}

// Clear removes all cached permission entries.
func (p *PermissionsClient) Clear() {
	if p == nil {
		return
	}
	p.mu.Lock()
	p.entries = make(map[string]cachedPermissionEntry)
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
	httpClient := p.httpClient
	if httpClient == nil {
		httpClient = http.DefaultClient
	}
	endpoint := strings.TrimRight(p.base, "/") + "/authz/permissions/" + url.PathEscape(userID)
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return nil, fmt.Errorf("create permissions request: %w", err)
	}
	request.Header.Set("Authorization", "Bearer "+token)
	response, err := httpClient.Do(request)
	if err != nil {
		return nil, fmt.Errorf("fetch permissions: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode < http.StatusOK || response.StatusCode >= http.StatusMultipleChoices {
		return nil, fmt.Errorf("fetch permissions: unexpected HTTP status %s", response.Status)
	}

	var payload struct {
		UserID  string `json:"user_id"`
		PermVer int64  `json:"perm_ver"`
		Grants  []struct {
			Key       string  `json:"key"`
			Condition *string `json:"condition"`
		} `json:"grants"`
	}
	if err := json.NewDecoder(response.Body).Decode(&payload); err != nil {
		return nil, fmt.Errorf("decode permissions: %w", err)
	}
	if payload.UserID != "" && payload.UserID != userID {
		return nil, fmt.Errorf("permissions response user_id %q does not match %q", payload.UserID, userID)
	}
	entry := &PermissionEntry{UserID: userID, PermVer: payload.PermVer, Grants: make([]Grant, 0, len(payload.Grants))}
	for _, wireGrant := range payload.Grants {
		permission, parseErr := Parse(wireGrant.Key)
		if parseErr != nil {
			continue
		}
		grant := Grant{Key: wireGrant.Key, permission: permission}
		if wireGrant.Condition != nil && strings.TrimSpace(*wireGrant.Condition) != "" {
			condition, compileErr := CompileCondition(*wireGrant.Condition)
			if compileErr != nil {
				continue
			}
			grant.Condition = condition
		}
		entry.Grants = append(entry.Grants, grant)
	}
	return entry, nil
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
	clone := &PermissionEntry{UserID: entry.UserID, PermVer: entry.PermVer, Grants: make([]Grant, len(entry.Grants))}
	copy(clone.Grants, entry.Grants)
	return clone
}
