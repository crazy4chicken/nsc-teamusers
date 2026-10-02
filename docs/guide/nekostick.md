---
title: Nekostick deployment
outline: 2
---

# Nekostick deployment

`teamusers` is a supervised Nekostick microservice, not a standalone
listener manager. Nekostick starts it as a child process, injects its leased
listener environment, captures its logs, performs health checks, and owns
supervision. The deployment extension installs a content-hashed static
Linux/amd64 binary; this repository supplies no separate runtime packaging.

## Build and install the binary

Build the artifact that the deployment extension will install:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' -o teamusers ./cmd/teamusers
```

The extension should place that binary at the `FileName` in the service entity
and manage its content hash. Keep the binary immutable after installation;
configuration and signing keys are runtime state.

## Service entity

Register the service as `targetType=Microservice` with an eager start mode. The
following is a concrete service definition using the entity fields
`FileName`, `ArgumentList`, `WorkingDirectory`, and `Environment`:

```json
{
  "Name": "teamusers",
  "TargetType": "Microservice",
  "FileName": "/opt/teamusers/teamusers",
  "ArgumentList": ["run"],
  "WorkingDirectory": "/var/lib/teamusers",
  "Environment": {
    "TEAMUSERS_CONNECTION_STRING": "<postgres-dsn-secret>",
    "TEAMUSERS_KEY_DIR": "/var/lib/teamusers/keys",
    "TEAMUSERS_NODE_ID": "teamusers",
    "TEAMUSERS_LOG_LEVEL": "info",
    "TEAMUSERS_NATS_URL": "",
    "TEAMUSERS_NOTIFICATION_ENDPOINTS": "",
    "TEAMUSERS_NOTIFICATION_SECRET": "<notification-secret>"
  },
  "StartMode": "Eager",
  "ForwardingMode": "Strip"
}
```

The exact Nekostick administration wrapper may serialize the policy fields with
its normal casing, but the service fields and values above are the contract.
Do not persist `PORT` or `HOST` as application overrides: Nekostick always adds
`PORT=<leased-port>` and `HOST=<loopback>` to every child environment. The
child must bind those values. `teamusers` resolves listener configuration
as **CLI flags > `TEAMUSERS_LISTEN_*` > supervisor `PORT`/`HOST` > defaults**, so
leave `TEAMUSERS_LISTEN_ADDRESS` and `TEAMUSERS_LISTEN_PORT` unset for a leased
listener. Set them only when deliberately overriding the lease.

The connection string and notification service secret in `Environment` are placeholders
above. Nekostick stores service `Environment` values as plaintext in its
PostgreSQL configuration; restrict access to the service entity, audit reads,
and backups accordingly. Never put real credentials in source control,
examples, logs, or the binary artifact.

Use `StartMode=Eager`: authentication is on the critical path of the rest of
the fleet, and Lazy mode can stall the first requests behind Nekostick's 30
second startup health window.

## svchost compose template

With the [svchost](https://github.com/crazy4chicken/nekostick-svchost)
extension, the service entity above becomes a declarative compose
configuration. The following `svchost-compose.yaml` is a complete template:

```yaml
strictSources: true
serviceScope: global
services:
  teamusers:
    source:
      # Pushing a v* tag builds and publishes teamusers_<version>_<arch>.zip
      # assets (x64, arm64) via the release workflow.
      release: "github:crazy4chicken/nsc-teamusers@v0.5.0"
      sha256: "<SHA-256 of teamusers_0.5.0_x64.zip>"
    args: ["run"]
    env:
      TEAMUSERS_CONNECTION_STRING: "postgres://teamusers:s3cret@10.0.0.2:5432/teamusers"
      TEAMUSERS_KEY_DIR: /var/lib/teamusers/keys
      TEAMUSERS_NODE_ID: teamusers
      TEAMUSERS_TOKEN_AUDIENCE: nekostick
      TEAMUSERS_WEBAUTHN_ORIGIN: "https://id.example.com"
      TEAMUSERS_NATS_URL: "nats://10.0.0.3:4222"
      TEAMUSERS_LOG_LEVEL: info
    start: eager    # authentication is on the fleet's critical path
    restart: on-failure
    health:
      type: http
      path: /healthz
      timeout: 5s
    route:
      prefix: /iam
      strip: true   # /iam/auth/login reaches the child as /auth/login
```

Notes:

- Only `TEAMUSERS_CONNECTION_STRING` is strictly required; the rest are the
  practical production set (audience, WebAuthn origin, NATS for event
  fan-out). Add OIDC/SCIM/audit-forwarding variables as those features are
  adopted.
- Do not pass `PORT`/`HOST` in `args` or `env`: the host injects them per
  launch, and `teamusers` binds the injected lease by default.
- The service CWD is the svchost service root, not the artifact directory —
  keep `TEAMUSERS_KEY_DIR` and any state paths absolute, as above.
- One `sha256` pins one architecture's ZIP; on mixed-architecture fleets
  either drop `strictSources` (the lock still pins the first observed
  digest per node) or split per-architecture documents under
  `serviceScope: document`.
- `route.prefix` + `strip: true` is the compose equivalent of
  `ForwardingMode=Strip`; the API is root-relative inside the child, so never
  drop `strip` unless the service is mounted at the site root.
- The health check type is `http` against `/healthz` (not the default
  `process` or a TCP check); `/readyz` remains available to the host for
  database-readiness gating.

## Listener leases

The supervisor supplies a loopback host and an allocated port before starting
the child. The child logs a structured `HTTP server serving` record with the
same effective address. Nekostick should associate the lease with that child,
then run the HTTP health check before forwarding requests. A configured
  `TEAMUSERS_LISTEN_PORT=0` is useful for local standalone development, but a
supervised child should consume the injected `PORT` so the lease is
unambiguous.

Do not expose the child listener outside the trusted Nekostick host boundary.
The service is plain HTTP; public TLS termination belongs to the external
reverse-proxy boundary.

## Routing and forwarding

The API is root-relative inside the child: it has no base-path or
`X-Forwarded-Prefix` support, and it does not need any. Nekostick's custom
route prefixes do the mapping. Use `targetType=Microservice`, publish the API
under a dedicated prefix such as `/iam/`, and keep the default
`ForwardingMode=Strip`: Nekostick removes the prefix before forwarding, so
`/iam/auth/login` reaches the child as `/auth/login`.

Routes to expose under that prefix:

- `GET /.well-known/jwks.json` for public signing keys.
- `/auth/*`: login, service credentials, refresh, logout, and introspection.
- `/authz/*`: service-only remote authorization and effective permissions.
- `/users*`, `/teams*`, `/groups*`, `/roles*`, `/permissions`, `/bindings*`,
  and `/audit` for the authenticated admin plane.

The complete method/path table and JSON contracts are in the [API reference](/api/overview).
`/healthz` and JWKS may be exposed only under the route policy intended for the
host; admin routes must not be public.

Health checks bypass the public route table: the supervisor probes the
child's leased listener directly at `GET /healthz`, which stays root-relative
regardless of the public prefix.

`ForwardingMode=Preserve` is only appropriate when exposing the service at
the site root with no prefix at all.

## Health checks and logs

Configure an HTTP health check (`GET /healthz`) for both startup and steady
state. `/healthz` returns `200 {"status":"ok"}` without querying PostgreSQL;
`/readyz` returns `200 {"status":"ready"}` only when the database `SELECT 1`
check succeeds, and `503 {"status":"not_ready"}` otherwise. Use `/readyz` as
an additional database-readiness signal or route gate, not as a substitute for
the required `/healthz` startup check. A TCP check is the Nekostick default,
but HTTP `/healthz` is preferred for this service.

Nekostick captures child stdout/stderr line by line. The service's JSON `slog`
records are single-line and fit the supervisor's 16 KiB line limit. Keep
operator-injected environment values and any wrapper output within the
supervisor's 200-lines/second and 1 MiB/second caps; never print DSNs, token
secrets, private keys, or notification service secrets.

## Forwarded client addresses

The HTTP middleware uses `X-Forwarded-For` only when the direct TCP peer is
loopback or matches a CIDR or IP configured in `TEAMUSERS_TRUSTED_PROXIES`. It
walks the forwarded chain from right to left, skips trusted proxy hops, and
uses the rightmost non-trusted address. For any other direct peer, the
forwarded header is ignored and the direct peer remains authoritative. This
protects login rate limits and audit metadata from forged client addresses.

The trusted edge proxy (Nekostick in this deployment) must overwrite, not
preserve or blindly append to, any client-supplied `X-Forwarded-For` value
with the source address it observes before forwarding. Prevent untrusted
clients from reaching the loopback upstream connection and preserve the
`Authorization` header when forwarding.

## TLS and shutdown

Terminate TLS at the external reverse proxy, then forward plain HTTP only over
the protected Nekostick boundary. This process does not terminate TLS.

For a restart or content-hash upgrade, Nekostick should start the new child,
wait for its `/healthz` check to pass, switch forwarding to the new instance,
and then drain the old instance. Send `SIGTERM` to the old process group; the
service stops accepting requests and drains HTTP handlers and event workers
within its ten-second budget. Nekostick provides a 15-second grace period and
uses `SIGKILL` only if the group has not exited. Never route new traffic to a
child after its drain begins.
