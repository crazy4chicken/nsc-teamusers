# API overview

## Use cases

Use this API when an application needs a small identity and authorization service rather than implementing account lifecycle, sessions, MFA, or policy evaluation itself. The surface is deliberately split into three planes:

- **Public authentication plane**: `/auth/*` and `/.well-known/jwks.json` handle registration, verification, login, token rotation, password recovery, invitations, and passkey login.
- **Self-service plane**: `/me/*` is for the currently authenticated user. It never accepts a service subject and never exposes password hashes, TOTP seeds, backup-code digests, or passkey public-key material.
- **Administrative plane**: `/users*`, `/teams*`, `/groups*`, `/roles*`, `/permissions*`, `/bindings*`, `/audit*`, and `/invitations*` are protected by a user bearer and the matching `iam:*` permission.
- **Service authorization plane**: `/authz/*` is service-only. It evaluates a user's effective grants for an application resource and returns a fail-closed decision.

See [authentication](./authentication.md), [self-service](./self-service.md), and [permissions](./permissions.md) for flow-specific examples.

## Base URL and Nekostick

The local base URL is `http://localhost:8080`. The service listens on the configured address and does not terminate TLS; deploy TLS at the reverse-proxy boundary. When Nekostick publishes teamusers with Strip mode, use `https://<host>/iam` as the external base URL. Nekostick removes `/iam` before forwarding, so requests sent to `https://<host>/iam/auth/login` arrive at teamusers as `/auth/login`.

Download the machine-readable contract from [`/openapi.yaml`](/openapi.yaml), or fetch it from the published documentation host:

```sh
curl -fsS https://<docs-host>/openapi.yaml -o openapi.yaml
```

The Go API server currently exposes `/healthz` and `/readyz` (not `/health`):

```sh
curl -i http://localhost:8080/healthz
curl -i http://localhost:8080/readyz
```


## Authentication classes

Access tokens are EdDSA JWTs issued by `teamusers`. They include `iss`, `sub`, `kind` (`user` or `service`), `perm_ver`, `iat`, `exp`, and an optional `team`. The access lifetime is ten minutes. Refresh tokens are opaque, rotated, and stored only as digests.

| Caller | Header | Typical endpoints |
| --- | --- | --- |
| Public client | None | `/auth/register`, `/auth/login`, `/auth/refresh`, JWKS |
| User bearer | `Authorization: Bearer <access-token>` | `/me/*` and administrative requests |
| Service bearer | `Authorization: Bearer <service-access-token>` | `/auth/introspect`, `/authz/*` |
| Admin subject | User bearer plus `iam:<area>:any` (or an allowed team grant) | `/users*`, `/teams*`, `/groups*`, `/roles*`, `/permissions*`, `/bindings*`, `/audit`, `/invitations*` |

A token becomes unusable when its user is inactive or its `perm_ver` no longer matches the database. Service tokens are not accepted by `/me` or the admin plane.

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

The committed [OpenAPI 3.1 document](/openapi.yaml) is the source of truth for request and response shapes, security requirements, examples, and error responses. Keep generated clients pinned to the version in `info.version` and review the API guide pages alongside changes to handlers.
