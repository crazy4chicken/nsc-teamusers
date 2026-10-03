# API docs automation

teamusers generates its OpenAPI document from route walking plus co-located
operation metadata, and renders the result into the API reference pages you
are reading. Both halves are published for reuse by other Go services in the
fleet:

| Artifact | Name | Purpose |
| --- | --- | --- |
| Go module | `github.com/crazy4chicken/nsc-teamusers/apidocs/go` | Pair `chi` routes with operation metadata, emit deterministic OpenAPI 3.1 |
| npm package | `teamusers-apidocs-vitepress` | Turn the emitted spec into VitePress reference pages |

The pipeline is: `doc.go` metadata → `genspec` command → `openapi.yaml` →
VitePress dynamic pages. The generator fails when a walked route has no
metadata or metadata matches no route, so the reference can never silently
drift from the router.

## Go side

Install the module (tags live in the teamusers repository as
`apidocs/go/vX.Y.Z`):

```sh
go get github.com/crazy4chicken/nsc-teamusers/apidocs/go@v0.1.0
```

### 1. Declare operation metadata

Next to your handlers, declare one `apidocs.Operation` per route. `Request`
and `Response` are zero values reflected into schemas; the examples are
rendered verbatim into the page.

```go
package httpapi

import apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

var DocOperations = []apidocs.Operation{
	{
		Method:      "GET",
		Path:        "/widgets/{id}",
		Tag:         "Widgets",
		Summary:     "Get a widget",
		Description: "Use to retrieve one widget by ULID.",
		Security:    "admin", // any non-empty value marks the op as bearer-protected
		Response:    Widget{},
		ResponseExample: map[string]any{
			"id": "01J8Z3WIDGET00000000001", "name": "sprocket",
		},
		Errors: []apidocs.ErrorDoc{
			{Status: 401, Code: "unauthorized", Title: "Unauthorized"},
			{Status: 404, Code: "not_found", Title: "Not Found"},
		},
	},
}
```

### 2. Generate the spec

Add a small command that walks your router and emits the document. The router
must be constructible without a database — `chi.Walk` only inspects route
patterns. If your constructors need dependencies, give them stubs at
generation time (teamusers does this in `internal/apidocsgen`; most services
can just call their plain constructors).

```go
// cmd/genspec/main.go
package main

import (
	"os"

	apidocs "github.com/crazy4chicken/nsc-teamusers/apidocs/go"

	"example.com/myservice/internal/httpapi"
)

func main() {
	router := httpapi.NewRouter() // any constructible root router

	operations, err := apidocs.Collect(router, httpapi.DocOperations, nil)
	if err != nil {
		panic(err) // route/metadata mismatch: fix doc.go or the route
	}

	out, err := os.Create("docs/public/openapi.yaml")
	if err != nil {
		panic(err)
	}
	defer out.Close()

	err = apidocs.Emit(operations, out, apidocs.EmitOptions{
		Title:   "MyService API",
		Version: "0.1.0",
		Servers: []apidocs.Server{{URL: "http://localhost:8080"}},
		// Zero SecurityScheme yields an http bearer JWT scheme; zero
		// PermissionExtension yields x-teamusers-permission, which the
		// VitePress renderer reads.
	})
	if err != nil {
		panic(err)
	}
}
```

### 3. Optional: derived permission lines

If your service gates routes with path-derivable permission keys, pass a
`apidocs.PermissionDeriver` to `Collect` instead of `nil`. The deriver returns
an `any`-scoped key and an optional team-scoped alternative; both render as a
**Required permission** line in the reference. teamusers' own deriver is
`cmd/genspec/main.go` in this repository. Per-operation extras that are not
path-derivable (step-up freshness, audience restrictions) belong in the
operation's `PermissionNote` field, which renders as a suffix on the same
line.

### 4. Git-ignore the output

`docs/public/openapi.yaml` is generated; add it to `.gitignore` and regenerate
it on demand (see the `predocs` hooks below).

## VitePress side

```sh
pnpm add -D vitepress teamusers-apidocs-vitepress
```

Add the two dynamic-route stubs under `docs/api/reference/`:

```ts
// docs/api/reference/[tag].paths.ts
import { renderApiReferencePaths } from 'teamusers-apidocs-vitepress'

export default {
  paths: renderApiReferencePaths
}
```

```md
<!-- docs/api/reference/[tag].md -->
<!-- @content -->
```

The loader reads `docs/public/openapi.yaml` relative to `process.cwd()` by
default; pass `specPath` to `createApiReferencePaths` for other layouts. One
page is generated per OpenAPI tag; write your own sidebar entries for
`/api/reference/` in `docs/.vitepress/config.mts` (the package ships content
only, not navigation).

Wire regeneration into the docs scripts so the spec is always fresh:

```jsonc
// package.json
{
  "scripts": {
    "docs:dev": "vitepress dev docs",
    "docs:build": "vitepress build docs",
    "predocs:dev": "go run ./cmd/genspec",
    "predocs:build": "go run ./cmd/genspec"
  }
}
```

The `predocs:*` hook runs automatically before the matching `docs:*` script.
(Only the teamusers repository itself needs the extra
`pnpm --filter teamusers-apidocs-vitepress build` step, because it consumes
the package from the workspace instead of the registry.)

## Checklist

1. `go get github.com/crazy4chicken/nsc-teamusers/apidocs/go@v0.1.0`
2. `DocOperations` next to handlers; `go run ./cmd/genspec` exits zero
3. `docs/public/openapi.yaml` git-ignored
4. `pnpm add -D teamusers-apidocs-vitepress`, two stub files, sidebar entries
5. `pnpm docs:build` renders one page per tag, permission lines included
