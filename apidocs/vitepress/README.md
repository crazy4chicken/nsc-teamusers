# teamusers-apidocs-vitepress

A VitePress paths loader that turns a consumer's OpenAPI document into API-reference pages, including `x-teamusers-permission` requirements.

## Consumer contract

Add a dynamic route stub at `docs/api/reference/[tag].paths.ts`:

```ts
import { renderApiReferencePaths } from 'teamusers-apidocs-vitepress'

export default {
  paths: renderApiReferencePaths
}
```

Add the content placeholder at `docs/api/reference/[tag].md`:

```md
<!-- @content -->
```

By default, the loader reads `docs/public/openapi.yaml` relative to the consumer site's `process.cwd()`. To use a different location, pass `specPath` to `createApiReferencePaths`; relative paths are also resolved from `process.cwd()`:

```ts
import { createApiReferencePaths } from 'teamusers-apidocs-vitepress'

export default {
  paths: createApiReferencePaths({ specPath: 'spec/openapi.yaml' })
}
```

An absolute `specPath` is also accepted. The package supplies the dynamic route content only; each consumer must write and maintain its own VitePress sidebar for `/api/reference/`.

Add `teamusers-apidocs-vitepress` and `vitepress` to the consumer docs site's `devDependencies`. `yaml` is this package's runtime dependency, not a peer dependency, so consumers do not need to install it separately.
