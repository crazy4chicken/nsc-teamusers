# AGENTS.md — teamusers

Standalone Go identity & access microservice for the Nekostick service fleet.
Single source of truth for users, teams, groups, roles, permissions,
credentials, sessions, and audit; issues EdDSA JWTs and serves JWKS for the
rest of the fleet. API-only (no UI), deployed as a Nekostick-supervised child
process behind a route prefix such as `/iam/`.

## Repository layout

```text
cmd/teamusers/          entrypoint: run / status / doctor / bootstrap-admin
cmd/genspec/            OpenAPI generator (routes + doc.go metadata -> YAML)
internal/
  config/               env + flag loading, secret redaction
  domain/               permission grammar, wildcard matcher, resolver (deny > allow)
  store/                pgx queries, goose migrations (embedded), session reaper
  authn/                argon2id, TOTP, passkeys, token issue/rotate, JWKS, self-service
  authz/                effective-set resolver, ABAC expr eval, /authz/check
  httpapi/              chi routers: runtime plane, /me plane, admin plane, middleware
  events/               outbox relay -> NATS JetStream; notify.* -> HMAC HTTP
  audit/                append-only audit writer
  apidocs/              route<->operation-metadata pairing, OpenAPI emission
migrations/             goose SQL, numbered NNNN_name.sql, Up/Down mandatory
sdk/go|ts|python/       local-verification SDKs (JWKS cache, perm cache, middleware)
test/                   end-to-end integration tests (TEAMUSERS_TEST_PG-gated)
docs/                   VitePress site; api/reference + public/openapi.yaml generated
PLAN.md                 backlog of UNFINISHED work only (see "Planning docs" below)
```

## Commands

```sh
go run ./cmd/teamusers run          # needs TEAMUSERS_CONNECTION_STRING etc.
go run ./cmd/teamusers doctor       # diagnose config/DB/keys
go run ./cmd/genspec                # regenerate docs/public/openapi.yaml
pnpm docs:dev / docs:build          # docs site (predocs hooks run genspec)
TEAMUSERS_TEST_PG='postgres://...' go test ./test/   # integration suite
```

Integration tests require a real PostgreSQL and skip when `TEAMUSERS_TEST_PG`
is unset. No in-memory substitute is accepted.

## Architecture invariants (do not break)

- **Tokens prove identity only.** Permissions are NEVER embedded in JWTs.
  Claims contract consumed by all three SDKs: `iss, aud, sub, team, kind,
  perm_ver, iat, exp, jti, auth_time, amr`. Additive-only; changing existing
  claim names/shapes is a breaking cross-repo change.
- **Effective set = direct bindings U group bindings -> roles -> permission
  keys**, minus failed ABAC conditions, expired bindings, disabled users.
  Explicit deny (`!` prefix) always beats allow; wildcards match within one
  segment only. Precedence rules live in `internal/domain/resolve.go` and
  have a dedicated test matrix — extend the matrix when changing rules.
- **Every authz-relevant mutation** runs in one transaction that also:
  writes an audit row, writes an outbox row, and bumps `perm_ver` of every
  affected user. Skipping any of the three silently breaks SDK caches.
- **Audit log is append-only.** No UPDATE/DELETE anywhere, ever.
- **Admin plane dogfoods the permission engine.** Every admin route is gated
  by an `iam:*` permission; new admin routes must register their key and
  check it.
- **Revocation semantics:** disable/revoke propagates within
  `min(access_token_TTL, cache_TTL)`, narrowed to seconds by events;
  `/authz/check` is always immediate. Document behavior honestly against
  this, never promise instant revocation.
- **Trust boundary:** the service binds loopback/leased port and trusts
  `X-Forwarded-For`/`X-Real-IP` only from loopback or configured
  `TEAMUSERS_TRUSTED_PROXIES`. Never widen this by default.
- **Outbox topics are a contract** with SDK subscribers: `perm.changed`,
  `user.disabled`, `role.updated`, `key.rotated`, `user.created`,
  `user.updated`, `user.deleted`, `team.created`, `team.updated` (-> `iam.*`
  subjects) plus `notify.*` and `audit.forward` (-> HMAC-signed HTTP).
  Consumers are idempotent by event id; keep payloads additive-only.

## Rules for changes

1. **New/changed route** -> register handler AND add/update its `Operation`
   metadata in `internal/httpapi/doc.go`. `internal/apidocs/collect.go`
   enforces bidirectional pairing: `go run ./cmd/genspec` fails if a walked
   route lacks metadata or metadata matches no route. Never hand-edit
   `docs/public/openapi.yaml` or `docs/api/reference/` (generated).
2. **Schema change** -> new `migrations/NNNN_name.sql` (next number, Up and
   Down), embedded via `migrations/embed.go`. Migrations run at startup
   behind an advisory lock; keep them idempotent-safe.
3. **New POST endpoints** must honor `Idempotency-Key` (24 h store) and
   return RFC 9457 problem+json errors; lists use cursor pagination.
4. **Permission keys** are data validated against
   `[!]resource:action:scope` at write time; scope is `own|team|any|*`.
5. **SDK parity:** authz semantics, claim shapes, event payloads, or
   endpoint behavior changes must be mirrored in `sdk/go`, `sdk/ts`,
   `sdk/python` (each has its own tests/CI publish workflow).
6. **Secrets:** never log credentials/tokens/keys; extend config redaction
   when adding secret-bearing config. Passwords stay argon2id.
7. **Tests:** behavior changes ship with integration coverage in `test/`
   against real Postgres; unit-test pure logic (matcher, expr sandbox,
   rotation state machine) next to the code.
8. **Events:** new authz-affecting mutation -> new/updated outbox topic +
   relay mapping + SDK handler. `notify.*` topics are notification-service
   directives, not fleet events; don't mix the two channels.

## Configuration surface

Env + flags, precedence: CLI > `TEAMUSERS_*` > `PORT`/`HOST` (Nekostick
injected) > defaults. Current env vars: `TEAMUSERS_CONNECTION_STRING`,
`TEAMUSERS_LISTEN_ADDRESS`, `TEAMUSERS_LISTEN_PORT`, `TEAMUSERS_KEY_DIR`,
`TEAMUSERS_NATS_URL`, `TEAMUSERS_NODE_ID`,
`TEAMUSERS_NOTIFICATION_ENDPOINTS`, `TEAMUSERS_NOTIFICATION_SECRET`,
`TEAMUSERS_REGISTRATION_MODE`, `TEAMUSERS_TOKEN_AUDIENCE`,
`TEAMUSERS_TRUSTED_PROXIES`, `TEAMUSERS_WEBAUTHN_ORIGIN`,
`TEAMUSERS_LOCKOUT_DURATION`, `TEAMUSERS_LOG_LEVEL`,
`TEAMUSERS_ACCESS_TOKEN_TTL`, `TEAMUSERS_REFRESH_TOKEN_TTL`,
`TEAMUSERS_SESSION_FAMILY_TTL` (defaults 10m/720h/2160h; family >= refresh),
`TEAMUSERS_AUDIT_RETENTION_DAYS` (default 0 = keep forever),
`TEAMUSERS_AUDIT_FORWARD_ENDPOINTS`, `TEAMUSERS_AUDIT_FORWARD_SECRET`,
`TEAMUSERS_LOGIN_ACTIVITY_RETENTION_DAYS` (default 90),
`TEAMUSERS_PWNED_PASSWORDS_ENABLED` (HIBP breach screening, default off).

Signing-key rotation: `POST /keys/rotate` (admin plane, `iam:keys:any`).
Retired keys stay in JWKS until `rotated_at + 2*max(access, mfa,
password-change TTL)`; multi-replica procedure is one POST + rolling restart
(see `docs/guide/operations.md`).

## Planning docs

`PLAN.md` records **unfinished work only** (backlog with evidence pointers).
When an item ships, delete it from PLAN.md and document the shipped behavior
in `docs/` if user-visible. Current design and architecture live in this
file and `docs/` — do not re-add design prose to PLAN.md.

## Deployment

Static binary (`CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build ./cmd/teamusers`),
no Dockerfile/systemd: Nekostick owns the process lifecycle, injects
`HOST`/`PORT`, supervises `GET /healthz`; `/readyz` gates on DB writability;
SIGTERM drains in 10 s. Nekostick service `Environment` is plaintext in its
PG config — treat Host Config API read access as high-sensitivity.
