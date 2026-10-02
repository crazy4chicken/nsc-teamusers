# Teamusers

[![License: AGPL v3](https://img.shields.io/badge/License-AGPL_v3-blue.svg)](LICENSE)
[![npm](https://img.shields.io/npm/v/teamusers-sdk)](https://www.npmjs.com/package/teamusers-sdk)
[![PyPI](https://img.shields.io/pypi/v/teamusers-sdk)](https://pypi.org/project/teamusers-sdk/)
[![Go Reference](https://pkg.go.dev/badge/github.com/crazy4chicken/nsc-teamusers/sdk/go.svg)](https://pkg.go.dev/github.com/crazy4chicken/nsc-teamusers/sdk/go)

`teamusers` is a standalone identity and access microservice for the
Nekostick service fleet: users, teams, groups, roles, permissions,
credentials, sessions, and audit — issuing EdDSA JWTs and serving JWKS for
the rest of the fleet.

## Features

- Password, TOTP 2FA (with backup codes), and passkey/WebAuthn
  authentication; OIDC inbound federation with PKCE.
- SCIM 2.0 inbound provisioning for external identity providers.
- RBAC with conditional (ABAC) bindings, wildcard matching, and explicit
  deny; the admin plane itself is gated by `iam:*` permissions.
- MFA enforcement policies, breached-password screening, and step-up
  authentication for sensitive operations.
- Refresh-token rotation with family reuse detection, session concurrency
  limits, and idle timeouts.
- Runtime signing-key rotation with overlapping JWKS publication.
- Audited, time-boxed admin impersonation.
- Append-only audit log with retention, streaming export, and HMAC-signed
  forwarding; lifecycle and permission events over NATS JetStream.
- Self-service registration (email verification, admin approval), `/me`
  profile/credential/session management, and login activity.

## Client SDKs

Verify tokens and check permissions locally — no introspection call on the
hot path. All three SDKs share the same claims contract, permission cache,
and middleware guards.

| Language | Package | Install |
| --- | --- | --- |
| Go | [`sdk/go`](sdk/go) | `go get github.com/crazy4chicken/nsc-teamusers/sdk/go` |
| TypeScript | [`sdk/ts`](sdk/ts) | `npm i teamusers-sdk` |
| Python | [`sdk/python`](sdk/python) | `pip install teamusers-sdk` |

See the [SDK usage guide](https://crazy4chicken.github.io/nsc-teamusers/guide/sdks)
for verification, authorization, step-up, and event-subscription examples.

## Quickstart

Start PostgreSQL 16 and create an empty database, then:

```sh
export TEAMUSERS_CONNECTION_STRING='postgres://<user>:<password>@127.0.0.1:5432/teamusers?sslmode=disable'
export TEAMUSERS_LISTEN_ADDRESS=127.0.0.1
export TEAMUSERS_LISTEN_PORT=8080
export TEAMUSERS_KEY_DIR="$PWD/data/keys"
go run ./cmd/teamusers run
```

Startup applies the embedded migrations and generates a signing key when
the key directory is empty. Verify with:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

Production builds are static Linux/amd64 binaries:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' -o teamusers ./cmd/teamusers
```

Deployment is handled by Nekostick (process lifecycle, `HOST`/`PORT`
injection, health supervision); see the
[deployment guide](https://crazy4chicken.github.io/nsc-teamusers/guide/nekostick).

## Documentation

<https://crazy4chicken.github.io/nsc-teamusers/>

Guides (getting started, security, operations, SDKs, deployment), the full
OpenAPI 3.1 reference, and configuration details.

## License

Licensed under the GNU Affero General Public License, Version 3.0. See
[LICENSE](LICENSE) or <https://www.gnu.org/licenses/agpl-3.0.html>.
