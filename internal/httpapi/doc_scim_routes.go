package httpapi

import (
	"github.com/go-chi/chi/v5"

	"teamusers/internal/apidocs"
	"teamusers/internal/config"
	"teamusers/internal/store"
)

func init() {
	apidocs.RegisterRouterChildBuilder(func(cfg config.Config, q store.Q) (chi.Router, error) {
		router := chi.NewRouter()
		router.Mount("/scim", NewSCIMRouter(q, cfg, nil))
		return router, nil
	})
}
