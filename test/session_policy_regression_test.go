package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"testing"
	"time"
)

func TestServiceSessionsIgnoreUserSessionPolicies(t *testing.T) {
	stack, _, adminToken := newAdminSession(t)
	ctx := context.Background()
	serviceUser := seedPasswordUser(t, ctx, stack.database.pool, "service-policy-user", "ServicePolicyPassword1")
	maxSessions, idleTimeoutMinutes := 1, 1
	insertSessionTestPolicy(t, ctx, stack, "service-exemption", "default", "", 100, &maxSessions, &idleTimeoutMinutes)

	status, body := stack.jsonRequest(t, http.MethodPost, "/users/"+serviceUser.ID+"/credentials", map[string]string{
		"kind": "service",
	}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create service credential status = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var credential credentialResponse
	decodeResponse(t, body, &credential)
	issueServicePair := func() tokenPair {
		t.Helper()
		status, body := stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
			"client_id": credential.ClientID, "client_secret": credential.ClientSecret,
		}, "")
		if status != http.StatusOK {
			t.Fatalf("issue service token status = %d, want %d: %s", status, http.StatusOK, body)
		}
		var pair tokenPair
		decodeResponse(t, body, &pair)
		assertTokenPair(t, pair)
		return pair
	}
	first := issueServicePair()
	_ = issueServicePair()
	firstID := refreshSessionID(first.RefreshToken)

	var activeSessions int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, serviceUser.ID).Scan(&activeSessions); err != nil {
		t.Fatalf("count service sessions: %v", err)
	}
	if activeSessions != 2 {
		t.Fatalf("active service sessions = %d, want 2 despite max-concurrent policy", activeSessions)
	}
	var storedKind string
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT client_meta->>'kind' FROM sessions WHERE id = $1`, firstID).Scan(&storedKind); err != nil {
		t.Fatalf("read service session kind: %v", err)
	}
	if storedKind != "service" {
		t.Fatalf("stored session kind = %q, want service", storedKind)
	}

	if _, err := stack.database.pool.Exec(ctx, `
		UPDATE sessions SET last_active_at = $2 WHERE id = $1`, firstID, time.Now().UTC().Add(-2*time.Hour)); err != nil {
		t.Fatalf("age service session activity: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{
		"refresh_token": first.RefreshToken,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("idle service refresh status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var replacement tokenPair
	decodeResponse(t, body, &replacement)
	assertTokenPair(t, replacement)

	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL`, serviceUser.ID).Scan(&activeSessions); err != nil {
		t.Fatalf("count service sessions after refresh: %v", err)
	}
	if activeSessions != 2 {
		t.Fatalf("active service sessions after refresh = %d, want 2", activeSessions)
	}
}

func TestConcurrentRefreshAndLoginUseUserBeforeSessionLocks(t *testing.T) {
	stack := newIntegrationStack(t)
	ctx := context.Background()
	user := seedPasswordUser(t, ctx, stack.database.pool, "session-lock-order-user", "SessionLockOrderPassword1")
	maxSessions := 1
	insertSessionTestPolicy(t, ctx, stack, "lock-order", "default", "", 100, &maxSessions, nil)
	initial := loginMeTestPair(t, stack, user.Username, "SessionLockOrderPassword1")

	type requestResult struct {
		name   string
		status int
		body   []byte
		err    error
	}
	start := make(chan struct{})
	ready := make(chan struct{}, 2)
	results := make(chan requestResult, 2)
	requestContext, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	launch := func(name, path string, requestBody any) {
		go func() {
			ready <- struct{}{}
			<-start
			status, body, err := postJSONWithContext(requestContext, stack, path, requestBody)
			results <- requestResult{name: name, status: status, body: body, err: err}
		}()
	}
	launch("refresh", "/auth/refresh", map[string]string{"refresh_token": initial.RefreshToken})
	launch("login", "/auth/login", map[string]string{
		"username": user.Username, "password": "SessionLockOrderPassword1",
	})
	<-ready
	<-ready
	close(start)

	statuses := make(map[string]int, 2)
	for range 2 {
		select {
		case result := <-results:
			if result.err != nil {
				t.Fatalf("concurrent %s request failed: %v", result.name, result.err)
			}
			statuses[result.name] = result.status
		case <-requestContext.Done():
			t.Fatalf("concurrent login/refresh did not finish: %v", requestContext.Err())
		}
	}
	if statuses["login"] != http.StatusOK {
		t.Fatalf("concurrent login status = %d, want %d", statuses["login"], http.StatusOK)
	}
	if statuses["refresh"] != http.StatusOK && statuses["refresh"] != http.StatusUnauthorized {
		t.Fatalf("concurrent refresh status = %d, want success or policy-revoked token", statuses["refresh"])
	}

	var activeSessions int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM sessions WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()`, user.ID).Scan(&activeSessions); err != nil {
		t.Fatalf("count sessions after concurrent login and refresh: %v", err)
	}
	if activeSessions != 1 {
		t.Fatalf("active sessions after concurrent login and refresh = %d, want 1", activeSessions)
	}
	var reuseEvents int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM outbox
		WHERE topic = 'notify.session.reuse_detected' AND payload->>'user_id' = $1`, user.ID).Scan(&reuseEvents); err != nil {
		t.Fatalf("count concurrent refresh reuse events: %v", err)
	}
	if reuseEvents != 0 {
		t.Fatalf("concurrent login/refresh generated %d reuse events, want 0", reuseEvents)
	}
}

func postJSONWithContext(ctx context.Context, stack *integrationStack, path string, body any) (int, []byte, error) {
	encoded, err := json.Marshal(body)
	if err != nil {
		return 0, nil, err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, stack.baseURL+path, bytes.NewReader(encoded))
	if err != nil {
		return 0, nil, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := stack.client.Do(request)
	if err != nil {
		return 0, nil, err
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		return 0, nil, err
	}
	return response.StatusCode, responseBody, nil
}

