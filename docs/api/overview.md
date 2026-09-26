# API overview

## Use cases

Use this API when an application needs a small identity and authorization service rather than implementing account lifecycle, sessions, MFA, or policy evaluation itself. The surface is deliberately split into three planes:

- **Public authentication plane**: `/auth/*` and `/.well-known/jwks.json` handle registration, verification, login, token rotation, password recovery, invitations, and passkey login.
- **Self-service plane**: `/me/*` is for the currently authenticated user. It never accepts a service subject and never exposes password hashes, TOTP seeds, backup-code digests, or passkey public-key material.
- **Administrative plane**: `/users*`, `/teams*`, `/groups*`, `/roles*`, `/permissions*`, `/bindings*`, `/audit*`, and `/invitations*` are protected by a user bearer and the matching `iam:*` permission.
- **Service authorization plane**: `/authz/*` is service-only. It evaluates a user's effective grants for an application resource and returns a fail-closed decision.

The per-area API reference pages are native VitePress pages derived at build time from the canonical OpenAPI document - for example [authentication](./reference/authentication), [self-service](./reference/self-service), and [permissions](./reference/permissions). Do not hand-edit generated reference output.

## Base URL and Nekostick

The local base URL is `http://localhost:8080`. The service listens on the configured address and does not terminate TLS; deploy TLS at the reverse-proxy boundary. When Nekostick publishes teamusers with Strip mode, use `https://<host>/iam` as the external base URL. Nekostick removes `/iam` before forwarding, so requests sent to `https://<host>/iam/auth/login` arrive at teamusers as `/auth/login`.

Download the machine-readable contract from [`openapi.yaml`](../openapi.yaml), or fetch it from the published documentation host:

```sh
curl -fsS https://<docs-host>/openapi.yaml -o openapi.yaml
```

The Go API server currently exposes `/healthz` and `/readyz` (not `/health`):

```sh
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```


## Authentication classes

Access tokens are EdDSA JWTs issued by `teamusers`. They include `iss`, `aud`,
`sub`, `kind` (`user` or `service`), `perm_ver`, `iat`, `exp`, and an optional
`team`. The access lifetime is ten minutes. Refresh tokens are opaque, rotated,
and stored only as digests.

| Caller | Header | Typical endpoints |
| --- | --- | --- |
| Public client | None | `/auth/register`, `/auth/login`, `/auth/refresh`, JWKS |
| User bearer | `Authorization: Bearer <access-token>` | `/me/*` and administrative requests |
| Service bearer | `Authorization: Bearer <service-access-token>` | `/auth/introspect`, `/authz/*` |
| Admin subject | User bearer plus `iam:<area>:any` (or an allowed team grant) | `/users*`, `/teams*`, `/groups*`, `/roles*`, `/permissions*`, `/bindings*`, `/audit`, `/invitations*` |

A token becomes unusable when its user is inactive or its `perm_ver` no longer matches the database. Service tokens are not accepted by `/me` or the admin plane.

Administrator-provisioned password credentials require a first-login change.
`POST /auth/login` returns `403 password_change_required` with a ten-minute
`change_token` instead of an access/refresh pair. Send it as the bearer token
to `POST /me/password` with the current and new passwords; only that endpoint
accepts this token. A successful change clears the requirement and revokes all
refresh sessions, so the user must sign in again.

## JSON and problem+json

Successful JSON responses use `Content-Type: application/json`. Failures use RFC 9457 `application/problem+json`:

```json
{
  "type": "about:blank",
  "title": "Invalid Request",
  "status": 400,
  "detail": "invalid_token",
  "instance": "request-id"
}
```

`type`, `title`, and `status` are always present. `detail` contains a stable error code where the handler defines one (`invalid_token`, `weak_password`, `account_locked`, `mfa_not_enrolled`, `insufficient_permissions`, and so on). `instance` is the request ID when middleware created one. Authentication and database failures intentionally use generic details. See [security](../guide/security.md) and the [permissions guide](../guide/permissions.md) for threat-model and authorization guidance.

## Idempotency for POST requests

All `POST` endpoints honor the optional `Idempotency-Key` header. The service
fingerprints the raw request body and retains the completed status and response
for 24 hours. A retry with the same key and body returns the identical status
and body with `Idempotency-Replayed: true`; `GET` and other non-`POST` requests
ignore the header.

When a key is already associated with a different body, the service returns
`422` with detail `idempotency_conflict`. A matching request that is still
executing returns `409` with detail `idempotency_in_progress`. `429` and `5xx`
responses, and responses larger than 64 KiB, are not retained. The key scope is
the SHA-256 digest of the raw `Authorization` header when present, otherwise
the resolved client IP.

## Cursor pagination

Collection endpoints accept `limit` and (except audit) an opaque `cursor`:

```sh
curl -sS -H "Authorization: Bearer $ADMIN_TOKEN" \
  'http://localhost:8080/users?limit=25&cursor='
```

The default limit is 100. Supplied limits must be positive; the backing store caps effective pages at 1000. Responses are shaped as `{ "items": [...], "next_cursor": "..." }`; an empty string means there is no next page. Pass the returned cursor unchanged to request the next page. Audit uses an integer cursor and returns `next_cursor: 0` when complete.

## Rate limiting and retries

Authentication endpoints are rate-limited by client IP and, for credential lookups, normalized login. Password verification also has bounded Argon2 worker capacity. Exhaustion returns `429` with detail `authentication temporarily busy`. Do not retry a password or MFA request in a tight loop; back off and preserve the same refresh-token rotation semantics. Logout and password-reset request deliberately hide account existence and return their documented idempotent status.

## Contract source

Go emits the single canonical OpenAPI 3.1 document from the handlers and `doc.go` metadata. The YAML is generated on demand by `go run ./cmd/genspec` (wired into `pnpm docs:dev`/`docs:build` as a pre-step) and is not committed; VitePress parses it at build time to derive the native pages under `docs/api/reference/`, so endpoint details remain in code rather than hand-edited pages.
