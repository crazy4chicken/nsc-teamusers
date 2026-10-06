package test

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
	"time"

	"teamusers/internal/config"
	"teamusers/internal/httpapi"
	"teamusers/internal/store"
)

const scimTestBearer = "scim-integration-test-secret"

type scimTestServer struct {
	database *integrationDatabase
	server   *httptest.Server
	client   *http.Client
}

func newSCIMTestServer(t *testing.T) *scimTestServer {
	t.Helper()
	database := newIntegrationDatabase(t)
	cfg := config.Config{
		ListenAddress:   "127.0.0.1",
		ScimBearerToken: scimTestBearer,
	}
	server := httpapi.NewServer(cfg, database.pool)
	server.Mount("/scim", httpapi.NewSCIMRouter(database.pool, cfg, nil))
	httpServer := httptest.NewServer(server.Handler())
	t.Cleanup(httpServer.Close)
	return &scimTestServer{
		database: database,
		server:   httpServer,
		client:   &http.Client{Timeout: 10 * time.Second},
	}
}

func createSCIMFixtureUser(t *testing.T, stack *scimTestServer, userName, status string, externalID, email *string) store.SCIMUser {
	t.Helper()
	user, err := store.CreateSCIMUser(context.Background(), stack.database.pool, store.User{
		Username: userName,
		Status:   status,
		Email:    email,
	}, externalID)
	if err != nil {
		t.Fatalf("create SCIM fixture user %q: %v", userName, err)
	}
	return user
}

func (s *scimTestServer) request(t *testing.T, method, path string, body any, bearer string, headers map[string]string) (int, http.Header, []byte) {
	t.Helper()
	var requestBody io.Reader
	if body != nil {
		encoded, err := json.Marshal(body)
		if err != nil {
			t.Fatalf("encode SCIM %s request: %v", method, err)
		}
		requestBody = bytes.NewReader(encoded)
	}
	request, err := http.NewRequestWithContext(context.Background(), method, s.server.URL+path, requestBody)
	if err != nil {
		t.Fatalf("build SCIM %s request: %v", method, err)
	}
	if body != nil {
		request.Header.Set("Content-Type", "application/scim+json")
	}
	if bearer != "" {
		request.Header.Set("Authorization", "Bearer "+bearer)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := s.client.Do(request)
	if err != nil {
		t.Fatalf("perform SCIM %s request: %v", method, err)
	}
	defer response.Body.Close()
	responseBody, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatalf("read SCIM %s response: %v", method, err)
	}
	return response.StatusCode, response.Header.Clone(), responseBody
}

func TestSCIMUsersCRUD(t *testing.T) {
	stack := newSCIMTestServer(t)
	disabledRouter := httpapi.NewSCIMRouter(nil, config.Config{}, nil)
	disabledRequest := httptest.NewRequest(http.MethodGet, "/v2/ServiceProviderConfig", nil)
	disabledResponse := httptest.NewRecorder()
	disabledRouter.ServeHTTP(disabledResponse, disabledRequest)
	if disabledResponse.Code != http.StatusUnauthorized || disabledResponse.Header().Get("Content-Type") != "application/problem+json" {
		t.Fatalf("disabled SCIM status/content type = %d/%q, want 401/problem+json", disabledResponse.Code, disabledResponse.Header().Get("Content-Type"))
	}

	status, headers, body := stack.request(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", nil, "", nil)
	if status != http.StatusUnauthorized || headers.Get("Content-Type") != "application/problem+json" {
		t.Fatalf("unauthenticated SCIM status/content type = %d/%q, want 401/problem+json: %s", status, headers.Get("Content-Type"), body)
	}
	status, _, _ = stack.request(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", nil, "wrong-token", nil)
	if status != http.StatusUnauthorized {
		t.Fatalf("invalid SCIM bearer status = %d, want %d", status, http.StatusUnauthorized)
	}

	status, headers, body = stack.request(t, http.MethodGet, "/scim/v2/ServiceProviderConfig", nil, scimTestBearer, nil)
	if status != http.StatusOK || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("SCIM ServiceProviderConfig status/content type = %d/%q, want 200/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}
	var providerConfig struct {
		Patch  struct{ Supported bool `json:"supported"` } `json:"patch"`
		Bulk   struct{ Supported bool `json:"supported"` } `json:"bulk"`
		Filter struct {
			Supported  bool `json:"supported"`
			MaxResults int  `json:"maxResults"`
		} `json:"filter"`
		Sort   struct{ Supported bool `json:"supported"` } `json:"sort"`
	}
	decodeResponse(t, body, &providerConfig)
	if !providerConfig.Patch.Supported || !providerConfig.Filter.Supported || providerConfig.Filter.MaxResults != 1000 || providerConfig.Bulk.Supported || providerConfig.Sort.Supported {
		t.Fatalf("SCIM ServiceProviderConfig capabilities = %+v", providerConfig)
	}
	status, headers, body = stack.request(t, http.MethodGet, "/scim/v2/Users?sortBy=userName", nil, scimTestBearer, nil)
	if status != http.StatusBadRequest || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("unsupported SCIM sort status/content type = %d/%q, want 400/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}

	status, headers, body = stack.request(t, http.MethodGet, "/scim/v2/ResourceTypes", nil, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("SCIM ResourceTypes status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var resourceTypes struct {
		Resources []struct {
			Name string `json:"name"`
		} `json:"Resources"`
	}
	decodeResponse(t, body, &resourceTypes)
	if len(resourceTypes.Resources) != 1 || resourceTypes.Resources[0].Name != "User" {
		t.Fatalf("SCIM ResourceTypes = %+v, want User only", resourceTypes.Resources)
	}
	status, headers, body = stack.request(t, http.MethodGet, "/scim/v2/Groups", nil, scimTestBearer, nil)
	if status != http.StatusNotImplemented || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("SCIM Groups status/content type = %d/%q, want 501/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}

	reservedEmail := "reserved@example.test"
	createSCIMFixtureUser(t, stack, "scim-unmanaged-email-owner", "active", nil, &reservedEmail)
	for _, testCase := range []struct {
		name string
		body map[string]any
	}{
		{name: "omitted", body: map[string]any{"userName": "missing-external-id"}},
		{name: "blank", body: map[string]any{"userName": "blank-external-id", "externalId": "  "}},
	} {
		responseStatus, _, responseBody := stack.request(t, http.MethodPost, "/scim/v2/Users", testCase.body, scimTestBearer, nil)
		if responseStatus != http.StatusBadRequest || !bytes.Contains(responseBody, []byte("invalidValue")) {
			t.Fatalf("SCIM create with %s externalId = %d %s, want 400 invalidValue", testCase.name, responseStatus, responseBody)
		}
	}
	invalidEmailStatus, _, invalidEmailBody := stack.request(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName":   "invalid-scim-email",
		"externalId": "directory-invalid-email",
		"emails":     []map[string]string{{"value": "not an email"}},
	}, scimTestBearer, nil)
	if invalidEmailStatus != http.StatusBadRequest || !bytes.Contains(invalidEmailBody, []byte("invalidValue")) {
		t.Fatalf("SCIM create with invalid email = %d %s, want 400 invalidValue", invalidEmailStatus, invalidEmailBody)
	}
	duplicateEmailStatus, _, duplicateEmailBody := stack.request(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName":   "duplicate-scim-email",
		"externalId": "directory-duplicate-email",
		"emails":     []map[string]any{{"value": reservedEmail, "primary": true}},
	}, scimTestBearer, nil)
	if duplicateEmailStatus != http.StatusConflict || !bytes.Contains(duplicateEmailBody, []byte("uniqueness")) {
		t.Fatalf("SCIM create with duplicate email = %d %s, want 409 uniqueness", duplicateEmailStatus, duplicateEmailBody)
	}

	createBody := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:schemas:core:2.0:User"},
		"userName":   "scim-user",
		"externalId": "directory-user-1",
		"name":       map[string]string{"givenName": "Ada", "familyName": "Lovelace"},
		"emails":     []map[string]any{{"value": "ada@example.test", "primary": true}},
	}
	idempotencyHeaders := map[string]string{"Idempotency-Key": "scim-user-create-1"}
	status, headers, body = stack.request(t, http.MethodPost, "/scim/v2/Users", createBody, scimTestBearer, idempotencyHeaders)
	if status != http.StatusCreated || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("create SCIM user status/content type = %d/%q, want 201/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}
	var created struct {
		ID          string `json:"id"`
		ExternalID  string `json:"externalId"`
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
		Active      bool   `json:"active"`
		Emails      []struct {
			Value   string `json:"value"`
			Primary bool   `json:"primary"`
		} `json:"emails"`
	}
	decodeResponse(t, body, &created)
	if created.ID == "" || created.ExternalID != "directory-user-1" || created.UserName != "scim-user" || created.DisplayName != "Ada Lovelace" || !created.Active || len(created.Emails) != 1 || created.Emails[0].Value != "ada@example.test" || !created.Emails[0].Primary {
		t.Fatalf("created SCIM user = %+v", created)
	}
	if headers.Get("Location") != "/scim/v2/Users/"+created.ID {
		t.Fatalf("SCIM create Location = %q, want user location", headers.Get("Location"))
	}

	status, headers, replayBody := stack.request(t, http.MethodPost, "/scim/v2/Users", createBody, scimTestBearer, idempotencyHeaders)
	if status != http.StatusCreated || headers.Get("Idempotency-Replayed") != "true" || !bytes.Equal(body, replayBody) {
		t.Fatalf("SCIM create replay status/header/body = %d/%q/%s, want cached 201 response: %s", status, headers.Get("Idempotency-Replayed"), replayBody, body)
	}

	status, _, body = stack.request(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": "SCIM-USER",
		"externalId": "directory-user-duplicate-name",
	}, scimTestBearer, nil)
	if status != http.StatusConflict {
		t.Fatalf("duplicate SCIM userName status = %d, want %d: %s", status, http.StatusConflict, body)
	}
	status, _, body = stack.request(t, http.MethodPost, "/scim/v2/Users", map[string]any{
		"userName": "another-scim-user",
		"externalId": "directory-user-1",
	}, scimTestBearer, nil)
	if status != http.StatusConflict {
		t.Fatalf("duplicate SCIM externalId status = %d, want %d: %s", status, http.StatusConflict, body)
	}

	status, headers, body = stack.request(t, http.MethodGet, "/scim/v2/Users/"+url.PathEscape(created.ID), nil, scimTestBearer, nil)
	if status != http.StatusOK || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("get SCIM user status/content type = %d/%q, want 200/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}

	filter := url.QueryEscape(`userName eq "scim-user"`)
	status, _, body = stack.request(t, http.MethodGet, "/scim/v2/Users?filter="+filter+"&startIndex=1&count=1", nil, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("list SCIM users status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var page struct {
		TotalResults int64 `json:"totalResults"`
		StartIndex   int   `json:"startIndex"`
		ItemsPerPage int   `json:"itemsPerPage"`
		Resources    []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	decodeResponse(t, body, &page)
	if page.TotalResults != 1 || page.StartIndex != 1 || page.ItemsPerPage != 1 || len(page.Resources) != 1 || page.Resources[0].ID != created.ID {
		t.Fatalf("filtered SCIM page = %+v", page)
	}

	invalidEmailPatch := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": `emails[type eq "work"].value`, "value": "not an email"}},
	}
	status, _, body = stack.request(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(created.ID), invalidEmailPatch, scimTestBearer, nil)
	if status != http.StatusBadRequest || !bytes.Contains(body, []byte("invalidValue")) {
		t.Fatalf("SCIM PATCH invalid email = %d %s, want 400 invalidValue", status, body)
	}
	duplicateEmailPatch := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": `emails[type eq "work"].value`, "value": reservedEmail}},
	}
	status, _, body = stack.request(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(created.ID), duplicateEmailPatch, scimTestBearer, nil)
	if status != http.StatusConflict || !bytes.Contains(body, []byte("uniqueness")) {
		t.Fatalf("SCIM PATCH duplicate email = %d %s, want 409 uniqueness", status, body)
	}

	invalidEmailPutStatus, _, invalidEmailPutBody := stack.request(t, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(created.ID), map[string]any{
		"userName": "invalid-put-email",
		"emails":   []map[string]any{{"value": "not an email"}},
		"active":   true,
	}, scimTestBearer, nil)
	if invalidEmailPutStatus != http.StatusBadRequest || !bytes.Contains(invalidEmailPutBody, []byte("invalidValue")) {
		t.Fatalf("SCIM PUT invalid email = %d %s, want 400 invalidValue", invalidEmailPutStatus, invalidEmailPutBody)
	}
	duplicateEmailPutStatus, _, duplicateEmailPutBody := stack.request(t, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(created.ID), map[string]any{
		"userName": "duplicate-put-email",
		"emails":   []map[string]any{{"value": reservedEmail}},
	}, scimTestBearer, nil)
	if duplicateEmailPutStatus != http.StatusConflict || !bytes.Contains(duplicateEmailPutBody, []byte("uniqueness")) {
		t.Fatalf("SCIM PUT duplicate email = %d %s, want 409 uniqueness", duplicateEmailPutStatus, duplicateEmailPutBody)
	}

	patchBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{
			{"op": "replace", "path": "name.formatted", "value": "Ada Lovelace Updated"},
			{"op": "replace", "path": "emails[primary eq true].value", "value": "ada-updated@example.test"},
			{"op": "replace", "path": "active", "value": false},
		},
	}
	status, headers, body = stack.request(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(created.ID), patchBody, scimTestBearer, nil)
	if status != http.StatusOK || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("patch SCIM user status/content type = %d/%q, want 200/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}
	var patched struct {
		DisplayName string `json:"displayName"`
		Active      bool   `json:"active"`
		Emails      []struct {
			Value string `json:"value"`
		} `json:"emails"`
	}
	decodeResponse(t, body, &patched)
	if patched.DisplayName != "Ada Lovelace Updated" || patched.Active || len(patched.Emails) != 1 || patched.Emails[0].Value != "ada-updated@example.test" {
		t.Fatalf("patched SCIM user = %+v", patched)
	}

	addEmailBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "add", "path": `emails[type eq "work"].value`, "value": "ada-work@example.test"}},
	}
	status, _, body = stack.request(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(created.ID), addEmailBody, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("SCIM PATCH add filtered work email = %d %s, want 200", status, body)
	}
	var addedEmail struct {
		Emails []struct {
			Value   string `json:"value"`
			Type    string `json:"type"`
			Primary bool   `json:"primary"`
		} `json:"emails"`
	}
	decodeResponse(t, body, &addedEmail)
	if len(addedEmail.Emails) != 1 || addedEmail.Emails[0].Value != "ada-work@example.test" || addedEmail.Emails[0].Type != "work" || !addedEmail.Emails[0].Primary {
		t.Fatalf("SCIM PATCH add filtered work email = %+v", addedEmail.Emails)
	}
	removeEmailBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "remove", "path": `emails[type eq "work"].value`}},
	}
	status, _, body = stack.request(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(created.ID), removeEmailBody, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("SCIM PATCH remove filtered work email = %d %s, want 200", status, body)
	}
	var removedEmail struct {
		Emails []struct {
			Value string `json:"value"`
		} `json:"emails"`
	}
	decodeResponse(t, body, &removedEmail)
	if len(removedEmail.Emails) != 0 {
		t.Fatalf("SCIM PATCH remove filtered work email left %+v", removedEmail.Emails)
	}

	enableBody := map[string]any{
		"schemas": []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
	}
	status, headers, body = stack.request(t, http.MethodPatch, "/scim/v2/Users/"+url.PathEscape(created.ID), enableBody, scimTestBearer, nil)
	if status != http.StatusOK || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("enable SCIM user status/content type = %d/%q, want 200/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}
	var enabled struct {
		Active bool `json:"active"`
	}
	decodeResponse(t, body, &enabled)
	if !enabled.Active {
		t.Fatal("SCIM PATCH active=true did not enable user")
	}

	replacementBody := map[string]any{
		"userName":   "scim-user-replaced",
		"externalId": "directory-user-2",
		"active":     true,
	}
	status, headers, body = stack.request(t, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(created.ID), replacementBody, scimTestBearer, nil)
	if status != http.StatusOK || headers.Get("Content-Type") != "application/scim+json" {
		t.Fatalf("replace SCIM user status/content type = %d/%q, want 200/application/scim+json: %s", status, headers.Get("Content-Type"), body)
	}
	var replaced struct {
		ID          string `json:"id"`
		ExternalID  string `json:"externalId"`
		UserName    string `json:"userName"`
		DisplayName string `json:"displayName"`
		Active      bool   `json:"active"`
		Emails      []any  `json:"emails"`
	}
	decodeResponse(t, body, &replaced)
	if replaced.ID != created.ID || replaced.ExternalID != "directory-user-2" || replaced.UserName != "scim-user-replaced" || replaced.DisplayName != "" || !replaced.Active || len(replaced.Emails) != 0 {
		t.Fatalf("replaced SCIM user = %+v", replaced)
	}
	if headers.Get("Location") != "/scim/v2/Users/"+created.ID {
		t.Fatalf("SCIM PUT Location = %q, want user location", headers.Get("Location"))
	}
	preserveExternalIDBody := map[string]any{
		"userName": "scim-user-put-preserved",
		"emails":   []map[string]any{{"value": "ada-put@example.test", "type": "work", "primary": true}},
		"active":   true,
	}
	status, _, body = stack.request(t, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(created.ID), preserveExternalIDBody, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("SCIM PUT without externalId = %d %s, want 200", status, body)
	}
	var preservedExternalID struct {
		ExternalID string `json:"externalId"`
		UserName   string `json:"userName"`
		Emails     []struct {
			Value string `json:"value"`
		} `json:"emails"`
	}
	decodeResponse(t, body, &preservedExternalID)
	if preservedExternalID.ExternalID != "directory-user-2" || preservedExternalID.UserName != "scim-user-put-preserved" || len(preservedExternalID.Emails) != 1 || preservedExternalID.Emails[0].Value != "ada-put@example.test" {
		t.Fatalf("SCIM PUT without externalId result = %+v", preservedExternalID)
	}

	blankExternalIDStatus, _, blankExternalIDBody := stack.request(t, http.MethodPut, "/scim/v2/Users/"+url.PathEscape(created.ID), map[string]any{
		"userName":   "must-not-be-applied",
		"externalId": "   ",
		"active":     false,
	}, scimTestBearer, nil)
	if blankExternalIDStatus != http.StatusBadRequest || !bytes.Contains(blankExternalIDBody, []byte("invalidValue")) {
		t.Fatalf("SCIM PUT with blank externalId = %d %s, want 400 invalidValue", blankExternalIDStatus, blankExternalIDBody)
	}
	status, headers, body = stack.request(t, http.MethodDelete, "/scim/v2/Users/"+url.PathEscape(created.ID), nil, scimTestBearer, nil)
	if status != http.StatusNoContent || headers.Get("Content-Type") != "application/scim+json" || len(body) != 0 {
		t.Fatalf("delete SCIM user status/content type/body = %d/%q/%s, want 204/application/scim+json/empty", status, headers.Get("Content-Type"), body)
	}
	status, _, body = stack.request(t, http.MethodGet, "/scim/v2/Users/"+url.PathEscape(created.ID), nil, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("get soft-deleted SCIM user status = %d, want %d: %s", status, http.StatusOK, body)
	}
	var disabled struct {
		Active bool `json:"active"`
	}
	decodeResponse(t, body, &disabled)
	if disabled.Active {
		t.Fatal("SCIM DELETE did not mark user inactive")
	}

	var auditRows, lifecycleRows, disabledRows int
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM audit_log WHERE actor_id = 'scim' AND target = $1`, created.ID).Scan(&auditRows); err != nil {
		t.Fatalf("count SCIM audit rows: %v", err)
	}
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM outbox WHERE topic IN ('user.created', 'user.updated') AND payload->>'user_id' = $1`, created.ID).Scan(&lifecycleRows); err != nil {
		t.Fatalf("count SCIM lifecycle rows: %v", err)
	}
	if err := stack.database.pool.QueryRow(context.Background(), `
		SELECT count(*) FROM outbox WHERE topic = 'user.disabled' AND payload->'user_ids' ? $1`, created.ID).Scan(&disabledRows); err != nil {
		t.Fatalf("count SCIM disabled events: %v", err)
	}
	if auditRows != 8 || lifecycleRows != 8 || disabledRows != 2 {
		t.Fatalf("SCIM audit/lifecycle/disabled rows = %d/%d/%d, want 8/8/2", auditRows, lifecycleRows, disabledRows)
	}
}

func TestSCIMPopulationAndProtectedTargets(t *testing.T) {
	stack := newSCIMTestServer(t)
	ctx := context.Background()

	eligibleExternalID := "directory-eligible"
	eligible := createSCIMFixtureUser(t, stack, "scim-eligible", "active", &eligibleExternalID, nil)
	privilegedExternalID := "directory-privileged"
	privileged := createSCIMFixtureUser(t, stack, "scim-privileged", "disabled", &privilegedExternalID, nil)
	role, err := store.CreateRole(ctx, stack.database.pool, store.Role{Name: "scim-protected-role"})
	if err != nil {
		t.Fatalf("create SCIM protected role: %v", err)
	}
	if _, err := store.CreatePermission(ctx, stack.database.pool, store.Permission{
		Key: "iam:keys:any", Description: "SCIM protected target integration", RegisteredBy: "integration",
	}); err != nil {
		t.Fatalf("create SCIM protected permission: %v", err)
	}
	if err := store.SetRolePermissions(ctx, stack.database.pool, role.ID, []string{"iam:keys:any"}); err != nil {
		t.Fatalf("grant SCIM protected role permission: %v", err)
	}
	if _, err := store.CreateRoleBinding(ctx, stack.database.pool, store.RoleBinding{
		RoleID: role.ID, SubjectKind: "user", SubjectID: privileged.ID,
	}); err != nil {
		t.Fatalf("bind SCIM protected role: %v", err)
	}

	serviceExternalID := "directory-service"
	serviceAccount := createSCIMFixtureUser(t, stack, "scim-service-account", "active", &serviceExternalID, nil)
	if _, err := store.CreateCredential(ctx, stack.database.pool, store.Credential{
		UserID: serviceAccount.ID, Kind: "service", Hash: "scim-test-service-secret",
	}); err != nil {
		t.Fatalf("create SCIM service credential: %v", err)
	}

	missingExternalID := createSCIMFixtureUser(t, stack, "scim-unmanaged", "active", nil, nil)
	erasedExternalID := "directory-erased"
	erased := createSCIMFixtureUser(t, stack, "scim-erased", "active", &erasedExternalID, nil)
	if _, err := stack.database.pool.Exec(ctx, `
		UPDATE users SET username = $2, email = $3, status = 'disabled' WHERE id = $1`,
		erased.ID, "deleted_"+erased.ID, "deleted_"+erased.ID+"@deleted.invalid"); err != nil {
		t.Fatalf("anonymize SCIM erased fixture: %v", err)
	}
	if err := store.ClearUserExternalID(ctx, stack.database.pool, erased.ID); err != nil {
		t.Fatalf("clear erased SCIM external ID: %v", err)
	}

	pendingExternalID := "directory-pending"
	pending := createSCIMFixtureUser(t, stack, "scim-pending", "pending", &pendingExternalID, nil)
	invitedExternalID := "directory-invited"
	invited := createSCIMFixtureUser(t, stack, "scim-invited", "invited", &invitedExternalID, nil)

	status, _, body := stack.request(t, http.MethodGet, "/scim/v2/Users?count=100", nil, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("list eligible SCIM population = %d %s, want 200", status, body)
	}
	var page struct {
		TotalResults int64 `json:"totalResults"`
		Resources    []struct {
			ID string `json:"id"`
		} `json:"Resources"`
	}
	decodeResponse(t, body, &page)
	listedIDs := make(map[string]bool, len(page.Resources))
	for _, resource := range page.Resources {
		listedIDs[resource.ID] = true
	}
	if page.TotalResults != 3 || len(page.Resources) != 3 || !listedIDs[eligible.ID] || !listedIDs[pending.ID] || !listedIDs[invited.ID] {
		t.Fatalf("SCIM list included protected users or reported an inconsistent count: total=%d resources=%v", page.TotalResults, listedIDs)
	}
	for _, id := range []string{privileged.ID, serviceAccount.ID, missingExternalID.ID, erased.ID} {
		if listedIDs[id] {
			t.Fatalf("SCIM list exposed protected or unmanaged user %s", id)
		}
	}
	status, _, body = stack.request(t, http.MethodGet, "/scim/v2/Users?count=0", nil, scimTestBearer, nil)
	if status != http.StatusOK {
		t.Fatalf("list SCIM population with count=0 = %d %s, want 200", status, body)
	}
	var emptyPage struct {
		TotalResults int64 `json:"totalResults"`
		ItemsPerPage int   `json:"itemsPerPage"`
		Resources    []any `json:"Resources"`
	}
	decodeResponse(t, body, &emptyPage)
	if emptyPage.TotalResults != 3 || emptyPage.ItemsPerPage != 0 || len(emptyPage.Resources) != 0 {
		t.Fatalf("SCIM count=0 page = %+v, want exact eligible total and no resources", emptyPage)
	}

	protected := []store.SCIMUser{privileged, serviceAccount, erased}
	for _, user := range protected {
		path := "/scim/v2/Users/" + url.PathEscape(user.ID)
		status, _, body = stack.request(t, http.MethodGet, path, nil, scimTestBearer, nil)
		if status != http.StatusNotFound {
			t.Fatalf("GET protected SCIM user %s = %d %s, want 404", user.ID, status, body)
		}
		for _, operation := range []struct {
			method string
			body   any
		}{
			{method: http.MethodPatch, body: map[string]any{
				"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
				"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "must-not-change"}},
			}},
			{method: http.MethodPut, body: map[string]any{
				"userName":   "must-not-change",
				"externalId": "directory-protected-replacement",
				"active":     false,
			}},
			{method: http.MethodDelete},
		} {
			status, _, body = stack.request(t, operation.method, path, operation.body, scimTestBearer, nil)
			if status != http.StatusForbidden {
				t.Fatalf("%s protected SCIM user %s = %d %s, want 403", operation.method, user.ID, status, body)
			}
		}
	}

	missingPath := "/scim/v2/Users/" + url.PathEscape(missingExternalID.ID)
	status, _, body = stack.request(t, http.MethodGet, missingPath, nil, scimTestBearer, nil)
	if status != http.StatusNotFound {
		t.Fatalf("GET unmanaged SCIM user = %d %s, want 404", status, body)
	}
	for _, operation := range []struct {
		method string
		body   any
	}{
		{method: http.MethodPatch, body: map[string]any{"Operations": []map[string]any{{"op": "replace", "path": "displayName", "value": "must-not-change"}}}},
		{method: http.MethodPut, body: map[string]any{"userName": "must-not-change", "externalId": "directory-unmanaged-replacement"}},
		{method: http.MethodDelete},
	} {
		status, _, body = stack.request(t, operation.method, missingPath, operation.body, scimTestBearer, nil)
		if status != http.StatusNotFound {
			t.Fatalf("%s unmanaged SCIM user = %d %s, want 404", operation.method, status, body)
		}
	}

	for _, user := range []store.SCIMUser{pending, invited} {
		path := "/scim/v2/Users/" + url.PathEscape(user.ID)
		activationPatch := map[string]any{
			"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
			"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
		}
		status, _, body = stack.request(t, http.MethodPatch, path, activationPatch, scimTestBearer, nil)
		if status != http.StatusForbidden {
			t.Fatalf("activate SCIM %s user via PATCH = %d %s, want 403", user.Status, status, body)
		}
		status, _, body = stack.request(t, http.MethodPut, path, map[string]any{
			"userName":   user.Username,
			"externalId": user.ExternalID,
			"active":     true,
		}, scimTestBearer, nil)
		if status != http.StatusForbidden {
			t.Fatalf("activate SCIM %s user via PUT = %d %s, want 403", user.Status, status, body)
		}
	}

	erasedPath := "/scim/v2/Users/" + url.PathEscape(erased.ID)
	activationPatch := map[string]any{
		"schemas":    []string{"urn:ietf:params:scim:api:messages:2.0:PatchOp"},
		"Operations": []map[string]any{{"op": "replace", "path": "active", "value": true}},
	}
	status, _, body = stack.request(t, http.MethodPatch, erasedPath, activationPatch, scimTestBearer, nil)
	if status != http.StatusForbidden {
		t.Fatalf("activate erased SCIM user = %d %s, want 403", status, body)
	}
}
