# Teamusers

`teamusers` is a standalone Go identity and access microservice for the
Nekostick service fleet. It owns users, teams, groups, roles, permissions,
password/service credentials, JWT/JWKS authentication, authorization checks,
and transactional audit/outbox events.

## Features

- Password, TOTP 2FA (with backup codes), and passkey/WebAuthn authentication
  with EdDSA JWTs and JWKS.
- Self-service registration with email verification and admin approval modes.
- Refresh-token rotation, family reuse detection, account lockout, and
  permission-version checks.
- Self-service `/me` plane: profile, password change, session and passkey
  management.
- RBAC plus conditional bindings for data-driven `resource:action:scope`
  permissions; the admin plane itself is gated by `iam:*:any` permissions.
- Runtime `/auth/*` and `/authz/*` APIs plus the authenticated admin CRUD plane
  with batch operations and CSV user import.
- Append-only audit log, PostgreSQL outbox relay, NATS JetStream, and
  HMAC-signed HTTP notifications to a notification service.
- `healthz`, `readyz`, `run`, `status`, `doctor`, and `bootstrap-admin`
  surfaces for supervision and initial setup.
- Static Linux/amd64 binary with Nekostick supervised-child deployment.

## Quickstart: local development

Start a local PostgreSQL 16 instance and create an empty database, then set a
DSN and listener for the child process:

```sh
export TEAMUSERS_CONNECTION_STRING='postgres://<user>:<password>@127.0.0.1:5432/teamusers?sslmode=disable'
export TEAMUSERS_LISTEN_ADDRESS=127.0.0.1
export TEAMUSERS_LISTEN_PORT=8080
export TEAMUSERS_KEY_DIR="$PWD/data/keys"
go run ./cmd/teamusers run
```

Startup applies the embedded migrations and generates a signing key when the
key directory is empty. In another terminal, check the process:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

For a Nekostick deployment, build and hand the static artifact to the
deployment extension:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' -o teamusers ./cmd/teamusers
```

Register a `targetType=Microservice` service entity with `FileName`,
`ArgumentList: ["run"]`, `WorkingDirectory`, and `Environment`. Nekostick
injects `HOST=127.0.0.1` and the leased `PORT`, starts the child eagerly, and
supervises `GET /healthz`. The API is root-relative inside the child, so
publish it under a custom prefix such as `/iam/` and keep the default `Strip`
forwarding mode: Nekostick removes the prefix before the request reaches the
child. The exact registration is in [the Nekostick guide](docs/guide/nekostick.md).

Keep real DSNs, notification service secrets, and signing keys in Nekostick's protected
configuration. Its service environment is stored as plaintext in PostgreSQL,
so restrict access to service definitions and backups.

## Documentation

The VitePress site is organized under `docs/`:

The published documentation is available at <https://crazy4chicken.github.io/nsc-teamusers/>.

VitePress uses the `/nsc-teamusers/` base path for both GitHub Pages and local previews.

- `docs/guide/` contains the getting-started, security, operations, permissions, and Nekostick guides.
- `docs/api/overview.md` documents cross-cutting conventions (authentication classes, problem+json, pagination, rate limiting).
- `docs/api/reference/` is generated at VitePress build time from the canonical OpenAPI document; do not hand-edit the generated reference output.
- `docs/public/openapi.yaml` is generated from the Go handlers and `doc.go` metadata and is not committed; `pnpm docs:dev`/`docs:build` regenerate it via `go run ./cmd/genspec` before VitePress derives the native reference pages from it.

Run `pnpm docs:dev` to preview the site locally, or `pnpm docs:build` to create a production build.

## License

Licensed under the GNU Affero General Public License, Version 3.0. See
[LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html>.
