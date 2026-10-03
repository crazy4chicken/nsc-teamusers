# apidocs

`github.com/crazy4chicken/nsc-teamusers/apidocs/go` is a standalone Go package for pairing operation metadata with walkable `chi` routes, reflecting schemas, and emitting deterministic OpenAPI 3.1 YAML.

## Consumer flow

1. Define a `[]apidocs.Operation` slice with metadata for the documented routes.
2. Build a `chi.Router` that exposes mounted child route trees to `chi.Walk`; use `apidocs.WithRoutes` when needed.
3. Call `apidocs.Collect(router, metadata, deriver)` to validate the route/metadata pairing and apply optional derived permissions. Pass `nil` when permission derivation is not needed.
4. Call `apidocs.Emit(operations, writer, options)` with the document title, version, servers, and security scheme.
