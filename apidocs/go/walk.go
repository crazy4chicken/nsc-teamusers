package apidocs

import (
	"net/http"

	"github.com/go-chi/chi/v5"
)

// WithRoutes keeps the runtime root handler while exposing child route trees
// to chi.Walk. The production server uses one dispatch mount; documentation
// needs the mounted child routes to be visible to route discovery.
func WithRoutes(root chi.Router, children ...chi.Router) (chi.Router, error) {
	routes := make([]chi.Route, 0)
	if root != nil {
		err := chi.Walk(root, func(method, path string, handler http.Handler, _ ...func(http.Handler) http.Handler) error {
			if path == "/" || path == "/*" {
				return nil
			}
			routes = append(routes, chi.Route{
				Pattern:  path,
				Handlers: map[string]http.Handler{method: handler},
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	for _, child := range children {
		if child == nil {
			continue
		}
		err := chi.Walk(child, func(method, path string, handler http.Handler, _ ...func(http.Handler) http.Handler) error {
			routes = append(routes, chi.Route{
				Pattern:  path,
				Handlers: map[string]http.Handler{method: handler},
			})
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return &routeView{Router: root, routes: routes}, nil
}

type routeView struct {
	chi.Router
	routes []chi.Route
}

func (r *routeView) Routes() []chi.Route { return r.routes }
