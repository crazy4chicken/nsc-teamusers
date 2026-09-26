package apidocs

import (
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/go-chi/chi/v5"
)

func collect(router chi.Router, metadata []Operation) ([]Operation, error) {
	if router == nil {
		return nil, fmt.Errorf("cannot collect operations from a nil router")
	}

	walked := make([]routeKey, 0)
	seenRoutes := make(map[string]struct{})
	err := chi.Walk(router, func(method, path string, _ http.Handler, _ ...func(http.Handler) http.Handler) error {
		key := operationKey(method, path)
		if _, seen := seenRoutes[key]; seen {
			return nil
		}
		seenRoutes[key] = struct{}{}
		walked = append(walked, routeKey{method: method, path: path})
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("walk router: %w", err)
	}

	byKey := make(map[string]Operation, len(metadata))
	for _, operation := range metadata {
		key := operationKey(operation.Method, operation.Path)
		if _, exists := byKey[key]; !exists {
			byKey[key] = operation
		}
	}

	operations := make([]Operation, 0, len(walked))
	for _, route := range walked {
		key := operationKey(route.method, route.path)
		operation, ok := byKey[key]
		if !ok {
			return nil, fmt.Errorf("walked route %s has no operation metadata", key)
		}
		operations = append(operations, operation)
	}
	missing := make([]string, 0)
	for key := range byKey {
		if _, ok := seenRoutes[key]; !ok {
			missing = append(missing, key)
		}
	}
	if len(missing) > 0 {
		sort.Strings(missing)
		return nil, fmt.Errorf("operation metadata matches no walked routes: %s", strings.Join(missing, ", "))
	}

	sort.Slice(operations, func(i, j int) bool {
		if operations[i].Path == operations[j].Path {
			return strings.ToUpper(operations[i].Method) < strings.ToUpper(operations[j].Method)
		}
		return operations[i].Path < operations[j].Path
	})
	return operations, nil
}

type routeKey struct {
	method string
	path   string
}

func operationKey(method, path string) string {
	return strings.ToUpper(strings.TrimSpace(method)) + " " + path
}
