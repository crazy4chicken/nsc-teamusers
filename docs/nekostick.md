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
  "ForwardingMode": "Preserve"
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

The complete method/path table and JSON contracts are in [api.md](api.md).
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

The HTTP middleware trusts `X-Forwarded-For` only when the direct TCP peer is a
loopback address. In that case it uses the first address in the header. For any
non-loopback peer, the forwarded header is ignored and the direct peer remains
authoritative. This protects login rate limits and audit metadata from forged
client addresses.

Nekostick should set one canonical `X-Forwarded-For` value on its loopback
upstream connection and prevent untrusted clients from reaching that
connection. Preserve the `Authorization` header when forwarding.

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
