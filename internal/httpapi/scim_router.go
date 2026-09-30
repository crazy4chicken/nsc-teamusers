package httpapi

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strconv"
	"strings"

	"github.com/go-chi/chi/v5"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	auditlog "teamusers/internal/audit"
	"teamusers/internal/config"
	"teamusers/internal/store"
)

const (
	scimMediaType                  = "application/scim+json"
	scimErrorSchema                = "urn:ietf:params:scim:api:messages:2.0:Error"
	scimListResponseSchema         = "urn:ietf:params:scim:api:messages:2.0:ListResponse"
	scimPatchOperationSchema       = "urn:ietf:params:scim:api:messages:2.0:PatchOp"
	scimUserSchema                 = "urn:ietf:params:scim:schemas:core:2.0:User"
	scimResourceTypeSchema         = "urn:ietf:params:scim:schemas:core:2.0:ResourceType"
	scimServiceProviderConfigSchema = "urn:ietf:params:scim:schemas:core:2.0:ServiceProviderConfig"
)

type scimHandler struct {
	q      store.Q
	audit  *auditlog.Writer
	logger *slog.Logger
}

// NewSCIMRouter constructs the SCIM 2.0 provisioning router with bearer auth.
func NewSCIMRouter(q store.Q, cfg config.Config, logger *slog.Logger) chi.Router {
	if logger == nil {
		logger = slog.Default()
	}
	h := &scimHandler{q: q, audit: auditlog.NewWriter(), logger: logger}
	router := chi.NewRouter()
	router.Use(scimBearerAuth(cfg.ScimBearerToken))
	router.Get("/v2/ServiceProviderConfig", h.serviceProviderConfig)
	router.Get("/v2/ResourceTypes", h.resourceTypes)
	router.Get("/v2/Users", h.listUsers)
	router.Post("/v2/Users", h.createUser)
	router.Get("/v2/Users/{id}", h.getUser)
	router.Patch("/v2/Users/{id}", h.patchUser)
	router.Put("/v2/Users/{id}", h.replaceUser)
	router.Delete("/v2/Users/{id}", h.deleteUser)
	router.Get("/v2/Groups", h.unsupportedGroups)
	router.NotFound(h.notFound)
	router.MethodNotAllowed(h.methodNotAllowed)
	return router
}

func scimBearerAuth(configured string) func(http.Handler) http.Handler {
	expected := []byte(configured)
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			presented, ok := scimBearerCredential(r.Header.Get("Authorization"))
			if len(expected) == 0 || !ok || subtle.ConstantTimeCompare([]byte(presented), expected) != 1 {
				w.Header().Set("WWW-Authenticate", `Bearer realm="scim", error="invalid_token"`)
				WriteProblem(w, r, http.StatusUnauthorized, "Unauthorized", "a valid SCIM bearer token is required")
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}

func scimBearerCredential(header string) (string, bool) {
	parts := strings.Fields(header)
	if len(parts) != 2 || !strings.EqualFold(parts[0], "Bearer") || parts[1] == "" {
		return "", false
	}
	return parts[1], true
}

type scimError struct {
	Schemas  []string `json:"schemas"`
	ScimType string   `json:"scimType,omitempty"`
	Detail   string   `json:"detail,omitempty"`
	Status   string   `json:"status"`
}

func writeSCIMJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", scimMediaType)
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeSCIMError(w http.ResponseWriter, status int, scimType, detail string) {
	writeSCIMJSON(w, status, scimError{
		Schemas:  []string{scimErrorSchema},
		ScimType: scimType,
		Detail:   detail,
		Status:   strconv.Itoa(status),
	})
}

type scimFeatureConfig struct {
	Supported bool `json:"supported"`
}

type scimBulkConfig struct {
	Supported      bool  `json:"supported"`
	MaxOperations  int   `json:"maxOperations,omitempty"`
	MaxPayloadSize int64 `json:"maxPayloadSize,omitempty"`
}

type scimFilterConfig struct {
	Supported  bool `json:"supported"`
	MaxResults int  `json:"maxResults,omitempty"`
}

type scimAuthenticationScheme struct {
	Type        string `json:"type"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	SpecURI     string `json:"specUri,omitempty"`
	Primary     bool   `json:"primary,omitempty"`
}

type scimServiceProviderConfig struct {
	Schemas               []string                  `json:"schemas"`
	Patch                 scimFeatureConfig         `json:"patch"`
	Bulk                  scimBulkConfig            `json:"bulk"`
	Filter                scimFilterConfig          `json:"filter"`
	ChangePassword        scimFeatureConfig         `json:"changePassword"`
	Sort                  scimFeatureConfig         `json:"sort"`
	ETag                  scimFeatureConfig         `json:"etag"`
	AuthenticationSchemes []scimAuthenticationScheme `json:"authenticationSchemes"`
}

type scimResourceTypeMeta struct {
	ResourceType string `json:"resourceType"`
}

type scimResourceType struct {
	Schemas  []string            `json:"schemas"`
	ID       string              `json:"id"`
	Name     string              `json:"name"`
	Endpoint string              `json:"endpoint"`
	Schema   string              `json:"schema"`
	Meta     scimResourceTypeMeta `json:"meta"`
}

type scimResourceTypesResponse struct {
	Schemas      []string          `json:"schemas"`
	TotalResults int               `json:"totalResults"`
	StartIndex   int               `json:"startIndex"`
	ItemsPerPage int               `json:"itemsPerPage"`
	Resources    []scimResourceType `json:"Resources"`
}

func (h *scimHandler) serviceProviderConfig(w http.ResponseWriter, _ *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scimServiceProviderConfig{
		Schemas:        []string{scimServiceProviderConfigSchema},
		Patch:          scimFeatureConfig{Supported: true},
		Bulk:           scimBulkConfig{Supported: false},
		Filter:         scimFilterConfig{Supported: true, MaxResults: 1000},
		ChangePassword: scimFeatureConfig{Supported: false},
		Sort:           scimFeatureConfig{Supported: false},
		ETag:           scimFeatureConfig{Supported: false},
		AuthenticationSchemes: []scimAuthenticationScheme{{
			Type:        "oauthbearertoken",
			Name:        "SCIM Bearer Token",
			Description: "Static bearer token authentication",
			SpecURI:     "https://www.rfc-editor.org/rfc/rfc6750",
			Primary:     true,
		}},
	})
}

func (h *scimHandler) resourceTypes(w http.ResponseWriter, _ *http.Request) {
	writeSCIMJSON(w, http.StatusOK, scimResourceTypesResponse{
		Schemas:      []string{scimListResponseSchema},
		TotalResults: 1,
		StartIndex:   1,
		ItemsPerPage: 1,
		Resources: []scimResourceType{{
			Schemas:  []string{scimResourceTypeSchema},
			ID:       "User",
			Name:     "User",
			Endpoint: "/Users",
			Schema:   scimUserSchema,
			Meta:     scimResourceTypeMeta{ResourceType: "ResourceType"},
		}},
	})
}

func (h *scimHandler) unsupportedGroups(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusNotImplemented, "", "SCIM Groups provisioning is not supported")
}

func (h *scimHandler) notFound(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusNotFound, "", "the requested SCIM resource was not found")
}

func (h *scimHandler) methodNotAllowed(w http.ResponseWriter, _ *http.Request) {
	writeSCIMError(w, http.StatusMethodNotAllowed, "", "the requested SCIM method is not supported")
}

func (h *scimHandler) writeStoreError(w http.ResponseWriter, r *http.Request, operation string, err error) {
	var scimProblem *scimRequestError
	if errors.As(err, &scimProblem) {
		writeSCIMError(w, scimProblem.status, scimProblem.scimType, scimProblem.detail)
		return
	}
	if errors.Is(err, pgx.ErrNoRows) {
		writeSCIMError(w, http.StatusNotFound, "", "the requested user was not found")
		return
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "23505":
			writeSCIMError(w, http.StatusConflict, "uniqueness", "userName or externalId already exists")
			return
		case "23503", "23514", "22P02":
			writeSCIMError(w, http.StatusBadRequest, "invalidValue", "the SCIM resource contains an invalid value")
			return
		}
	}
	if h.logger != nil {
		h.logger.ErrorContext(r.Context(), "SCIM store operation failed", "operation", operation)
	}
	writeSCIMError(w, http.StatusInternalServerError, "", "the SCIM request could not be completed")
}
