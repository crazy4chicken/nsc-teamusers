# Teamusers

`teamusers` is a standalone Go identity and access microservice for the
Nekostick service fleet. It owns users, teams, groups, roles, permissions,
password/service credentials, JWT/JWKS authentication, authorization checks,
and transactional audit/outbox events.

## Features

- Password and service-account token issuance with EdDSA JWTs and JWKS.
- Refresh-token rotation, family reuse detection, and permission-version checks.
- RBAC plus conditional bindings for data-driven `resource:action:scope` permissions.
- Runtime `/auth/*` and `/authz/*` APIs plus an authenticated admin CRUD plane.
- Append-only audit log, PostgreSQL outbox relay, NATS JetStream, and HMAC-signed HTTP notifications to a notification service.
- `healthz`, `readyz`, `run`, `status`, and `doctor` surfaces for supervision.
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
child. The exact registration is in [the Nekostick guide](docs/nekostick.md).

Keep real DSNs, notification service secrets, and signing keys in Nekostick's protected
configuration. Its service environment is stored as plaintext in PostgreSQL,
so restrict access to service definitions and backups.

## Documentation

- [HTTP API reference](docs/api.md)
- [Operations runbook](docs/operations.md)
- [Nekostick deployment and integration](docs/nekostick.md)
- [Authentication security notes](docs/security.md)
- [Implementation plan](PLAN.md)

The binary supports `run`, `status`, and `doctor`. Configuration knobs and
CLI flag names are documented in the operations runbook and implemented in
`internal/config`.

## License

Licensed under the GNU Affero General Public License, Version 3.0. See
[LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html>.
