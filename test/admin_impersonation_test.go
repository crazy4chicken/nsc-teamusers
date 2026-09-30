package test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"teamusers/internal/store"
)

func TestAdminImpersonationClaimsAuditAndNoRefresh(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	ctx := context.Background()
	target := seedPasswordUser(t, ctx, stack.database.pool, "impersonation-target", "ImpersonationTargetPassword1")

	requestBody := map[string]any{"user_id": target.ID, "reason": "support case review"}
	headers := map[string]string{"Idempotency-Key": "impersonation-default-ttl"}
	status, body := stack.jsonRequestHeaders(t, http.MethodPost, "/impersonations", requestBody, adminToken, headers)
	if status != http.StatusOK {
		t.Fatalf("impersonation status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var first struct {
		AccessToken string    `json:"access_token"`
		TokenType   string    `json:"token_type"`
		ExpiresAt   time.Time `json:"expires_at"`
	}
	decodeResponse(t, body, &first)
	if first.AccessToken == "" || first.TokenType != "Bearer" || first.ExpiresAt.IsZero() {
		t.Fatalf("impersonation response = %+v", first)
	}
	var responseFields map[string]json.RawMessage
	decodeResponse(t, body, &responseFields)
	if _, ok := responseFields["refresh_token"]; ok {
		t.Fatalf("impersonation response includes refresh_token: %s", body)
	}
	assertImpersonationClaims(t, first.AccessToken, admin.ID, target.ID, 300)
	var firstClaims struct {
		JTI string `json:"jti"`
		Exp int64  `json:"exp"`
	}
	decodeTokenClaims(t, first.AccessToken, &firstClaims)
	if firstClaims.JTI == "" {
		t.Fatal("impersonation access token is missing jti")
	}
	if !first.ExpiresAt.Equal(time.Unix(firstClaims.Exp, 0).UTC()) {
		t.Fatalf("expires_at = %s, token exp = %s", first.ExpiresAt, time.Unix(firstClaims.Exp, 0).UTC())
	}

	status, replay := stack.jsonRequestHeaders(t, http.MethodPost, "/impersonations", requestBody, adminToken, headers)
	if status != http.StatusOK || string(replay) != string(body) {
		t.Fatalf("idempotent impersonation replay = %d %s, want original response %s", status, replay, body)
	}

	status, body = stack.jsonRequest(t, http.MethodGet, "/me", nil, first.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("impersonation token GET /me = %d, want %d: %s", status, http.StatusOK, body)
	}
	var profile struct {
		ID string `json:"id"`
	}
	decodeResponse(t, body, &profile)
	if profile.ID != target.ID {
		t.Fatalf("impersonation token subject = %q, want %q", profile.ID, target.ID)
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/users/"+admin.ID+"/credentials", map[string]string{"kind": "service"}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create introspection service credential = %d, want %d: %s", status, http.StatusCreated, body)
	}
	var serviceCredential credentialResponse
	decodeResponse(t, body, &serviceCredential)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/client-credentials", map[string]string{
		"client_id": serviceCredential.ClientID, "client_secret": serviceCredential.ClientSecret,
	}, "")
	if status != http.StatusOK {
		t.Fatalf("issue introspection service token = %d, want %d: %s", status, http.StatusOK, body)
	}
	var servicePair tokenPair
	decodeResponse(t, body, &servicePair)
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/introspect", map[string]string{
		"token": first.AccessToken,
	}, servicePair.AccessToken)
	if status != http.StatusOK {
		t.Fatalf("impersonation introspection = %d, want %d: %s", status, http.StatusOK, body)
	}
	var introspection introspectionResponse
	decodeResponse(t, body, &introspection)
	if !introspection.Active || introspection.Kind != "user" || introspection.Subject != target.ID ||
		!introspection.Imp || introspection.Act["sub"] != admin.ID {
		t.Fatalf("impersonation introspection = %+v, want active target with act.sub=%s and imp=true", introspection, admin.ID)
	}

	for _, testCase := range []struct {
		method string
		path   string
	}{
		{method: http.MethodPost, path: "/me/passkeys/register/begin"},
		{method: http.MethodPost, path: "/me/passkeys/register/finish"},
		{method: http.MethodGet, path: "/me/passkeys"},
		{method: http.MethodPost, path: "/me/totp/enroll"},
		{method: http.MethodPost, path: "/me/totp/confirm"},
		{method: http.MethodPost, path: "/me/totp/backup-codes"},
		{method: http.MethodDelete, path: "/me/totp"},
	} {
		t.Run(testCase.method+" "+testCase.path, func(t *testing.T) {
			status, body := stack.jsonRequest(t, testCase.method, testCase.path, nil, first.AccessToken)
			if status != http.StatusForbidden || !strings.Contains(string(body), "impersonation_forbidden") {
				t.Fatalf("%s %s = %d %s, want impersonation_forbidden 403", testCase.method, testCase.path, status, body)
			}
		})
	}

	status, body = stack.jsonRequest(t, http.MethodPost, "/impersonations", map[string]any{
		"user_id": target.ID, "reason": "extended support review", "ttl_seconds": 900,
	}, adminToken)
	if status != http.StatusOK {
		t.Fatalf("maximum-TTL impersonation status = %d, want %d: %s", status, http.StatusOK, body)
	}

	var maximum struct {
		AccessToken string `json:"access_token"`
	}
	decodeResponse(t, body, &maximum)
	assertImpersonationClaims(t, maximum.AccessToken, admin.ID, target.ID, 900)
	var maximumClaims struct {
		JTI string `json:"jti"`
		Exp int64  `json:"exp"`
	}
	decodeTokenClaims(t, maximum.AccessToken, &maximumClaims)

	status, body = stack.jsonRequest(t, http.MethodPost, "/impersonations", map[string]any{
		"user_id": target.ID, "reason": "invalid TTL", "ttl_seconds": 901,
	}, adminToken)
	if status != http.StatusBadRequest {
		t.Fatalf("over-limit impersonation TTL status = %d, want %d: %s", status, http.StatusBadRequest, body)
	}

	var sessions int
	if err := stack.database.pool.QueryRow(ctx, `SELECT count(*) FROM sessions WHERE user_id = $1`, target.ID).Scan(&sessions); err != nil {
		t.Fatalf("count target sessions after impersonation: %v", err)
	}
	if sessions != 0 {
		t.Fatalf("target sessions after impersonation = %d, want none", sessions)
	}

	var auditCount int
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT count(*) FROM audit_log WHERE action = 'impersonation.started' AND target = $1`, target.ID).Scan(&auditCount); err != nil {
		t.Fatalf("count impersonation audit rows: %v", err)
	}
	if auditCount != 2 {
		t.Fatalf("impersonation audit rows = %d, want two successful issuances", auditCount)
	}
	var actorID string
	var auditTarget string
	var diff []byte
	if err := stack.database.pool.QueryRow(ctx, `
		SELECT actor_id, target, diff FROM audit_log
		WHERE action = 'impersonation.started' AND target = $1 ORDER BY id DESC LIMIT 1`, target.ID).
		Scan(&actorID, &auditTarget, &diff); err != nil {
		t.Fatalf("read impersonation audit row: %v", err)
	}
	var changes struct {
		After struct {
			Actor      string    `json:"actor"`
			Target     string    `json:"target"`
			Reason     string    `json:"reason"`
			TTLSeconds int64     `json:"ttl_seconds"`
			JTI        string    `json:"jti"`
			ExpiresAt  time.Time `json:"expires_at"`
		} `json:"after"`
	}
	if err := json.Unmarshal(diff, &changes); err != nil {
		t.Fatalf("decode impersonation audit diff: %v", err)
	}
	if actorID != admin.ID || auditTarget != target.ID || changes.After.Actor != admin.ID || changes.After.Target != target.ID ||
		changes.After.Reason != "extended support review" || changes.After.TTLSeconds != 900 || changes.After.JTI != maximumClaims.JTI ||
		!changes.After.ExpiresAt.Equal(time.Unix(maximumClaims.Exp, 0).UTC()) {
		t.Fatalf("impersonation audit = actor %q target %q diff %+v, maximum token jti=%q exp=%d", actorID, auditTarget, changes.After, maximumClaims.JTI, maximumClaims.Exp)
	}
}

func TestAdminImpersonationGuards(t *testing.T) {
	stack, admin, adminToken := newAdminSession(t)
	ctx := context.Background()

	disabled := seedPasswordUser(t, ctx, stack.database.pool, "impersonation-disabled", "ImpersonationDisabledPassword1")
	if _, err := stack.database.pool.Exec(ctx, `UPDATE users SET status = 'disabled' WHERE id = $1`, disabled.ID); err != nil {
		t.Fatalf("disable impersonation target: %v", err)
	}

	privileged := seedPasswordUser(t, ctx, stack.database.pool, "impersonation-iam-target", "ImpersonationIAMPassword1")
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "impersonation-target-admin"})
	if err != nil {
		t.Fatalf("create privileged target role: %v", err)
	}
	if err := store.SetRolePermissions(ctx, stack.database.pool, role.ID, []string{"iam:keys:any"}); err != nil {
		t.Fatalf("grant IAM permission to target role: %v", err)
	}
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: privileged.ID,
	}); err != nil {
		t.Fatalf("bind privileged target role: %v", err)
	}

	serviceAccount := seedPasswordUser(t, ctx, stack.database.pool, "impersonation-service", "ImpersonationServicePassword1")
	status, body := stack.jsonRequest(t, http.MethodPost, "/users/"+serviceAccount.ID+"/credentials", map[string]string{"kind": "service"}, adminToken)
	if status != http.StatusCreated {
		t.Fatalf("create target service credential = %d, want %d: %s", status, http.StatusCreated, body)
	}

	for _, testCase := range []struct {
		name   string
		userID string
	}{
		{name: "disabled target", userID: disabled.ID},
		{name: "target with effective IAM permission", userID: privileged.ID},
		{name: "self impersonation", userID: admin.ID},
		{name: "service account", userID: serviceAccount.ID},
	} {
		t.Run(testCase.name, func(t *testing.T) {
			status, body := stack.jsonRequest(t, http.MethodPost, "/impersonations", map[string]string{
				"user_id": testCase.userID, "reason": "support case review",
			}, adminToken)
			if status != http.StatusForbidden {
				t.Fatalf("impersonation of %s = %d, want %d: %s", testCase.name, status, http.StatusForbidden, body)
			}
		})
	}
}

func TestAdminImpersonationRequiresStepUp(t *testing.T) {
	stack, admin, _ := newAdminSession(t)
	status, body := stack.jsonRequest(t, http.MethodPost, "/auth/login", map[string]string{
		"username": admin.Username, "password": "admin-password",
	}, "")
	if status != http.StatusOK {
		t.Fatalf("fresh admin login = %d, want %d: %s", status, http.StatusOK, body)
	}
	var original tokenPair
	decodeResponse(t, body, &original)

	if _, err := stack.database.pool.Exec(context.Background(), `
		UPDATE sessions SET client_meta = client_meta - 'auth_time' WHERE id = $1`, refreshSessionID(original.RefreshToken)); err != nil {
		t.Fatalf("make admin session auth_time missing: %v", err)
	}
	status, body = stack.jsonRequest(t, http.MethodPost, "/auth/refresh", map[string]string{"refresh_token": original.RefreshToken}, "")
	if status != http.StatusOK {
		t.Fatalf("refresh with missing auth_time = %d, want %d: %s", status, http.StatusOK, body)
	}
	var stale tokenPair
	decodeResponse(t, body, &stale)
	if got := tokenAuthTime(t, stale.AccessToken); got != 0 {
		t.Fatalf("refreshed auth_time = %d, want 0", got)
	}

	target := seedPasswordUser(t, context.Background(), stack.database.pool, "impersonation-step-up-target", "ImpersonationStepUpPassword1")
	status, body = stack.jsonRequest(t, http.MethodPost, "/impersonations", map[string]string{
		"user_id": target.ID, "reason": "support case review",
	}, stale.AccessToken)
	if status != http.StatusForbidden || !strings.Contains(string(body), "step_up_required") {
		t.Fatalf("stale-auth impersonation = %d %s, want step_up_required 403", status, body)
	}
}

func assertImpersonationClaims(t *testing.T, rawToken, actorID, targetID string, expectedTTL int64) {
	t.Helper()
	var claims struct {
		Subject  string          `json:"sub"`
		Kind     string          `json:"kind"`
		Actor    json.RawMessage `json:"act"`
		Imperson bool            `json:"imp"`
		AuthTime int64           `json:"auth_time"`
		IssuedAt int64           `json:"iat"`
		Expires  int64           `json:"exp"`
		JTI      string          `json:"jti"`
		AMR      []string        `json:"amr"`
	}
	decodeTokenClaims(t, rawToken, &claims)
	if claims.Subject != targetID || claims.Kind != "user" || !claims.Imperson || claims.AuthTime != 0 {
		t.Fatalf("impersonation claims = %+v", claims)
	}
	var actor map[string]string
	if err := json.Unmarshal(claims.Actor, &actor); err != nil {
		t.Fatalf("decode actor claim: %v", err)
	}
	if len(actor) != 1 || actor["sub"] != actorID {
		t.Fatalf("act claim = %v, want {sub:%q}", actor, actorID)
	}
	if claims.JTI == "" {
		t.Fatal("impersonation access token is missing jti")
	}
	if claims.Expires-claims.IssuedAt != expectedTTL || claims.Expires-claims.IssuedAt > 900 {
		t.Fatalf("impersonation TTL = %d seconds, want %d", claims.Expires-claims.IssuedAt, expectedTTL)
	}
	if len(claims.AMR) != 1 || claims.AMR[0] != "impersonation" {
		t.Fatalf("impersonation amr = %v, want [impersonation]", claims.AMR)
	}
}

func decodeTokenClaims(t *testing.T, rawToken string, destination any) {
	t.Helper()
	parts := strings.Split(rawToken, ".")
	if len(parts) != 3 {
		t.Fatalf("access token has %d segments, want 3", len(parts))
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		t.Fatalf("decode access token payload: %v", err)
	}
	if err := json.Unmarshal(payload, destination); err != nil {
		t.Fatalf("decode access token claims: %v", err)
	}
}
