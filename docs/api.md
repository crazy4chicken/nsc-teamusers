# HTTP API

The service listens on the address selected by `NSC_TU_LISTEN_ADDRESS` and
`NSC_TU_LISTEN_PORT`. It serves JSON over plain HTTP; TLS termination belongs
to the Nekostick/reverse-proxy boundary. If a proxy publishes the service under
a prefix such as `/iam`, it must remove that prefix before forwarding (the
service routes the paths below at the root).

## Authentication classes

| Class | Meaning |
| --- | --- |
| Public | No bearer token is required. |
| User bearer | `Authorization: Bearer <access-token>` for an active user or service subject. The token's `perm_ver` must still match the user row. |
| Service-only | A valid active access token whose JWT `kind` claim is `service`. |
| Admin-subject | A valid active bearer subject. The current admin router checks that a subject exists; it does not yet enforce an `iam:*` permission. |

Access tokens are EdDSA JWTs. The issuer is `nsc-teamusers`; the claims include
`iss`, `sub`, `kind` (`user` or `service`), `perm_ver`, `iat`, `exp`, `jti`, and
`team` when the user has an active team. Access tokens expire after 10 minutes.

## Common response types

The following shapes use the JSON field names emitted by the service. Timestamp
values are RFC 3339 strings.

```json
{
  "id": "01J...",
  "username": "alice",
  "email": "alice@example.test",
  "display_name": "Alice",
  "status": "active",
  "perm_ver": 0,
  "created_at": "2026-01-01T00:00:00Z",
  "updated_at": "2026-01-01T00:00:00Z"
}
```

The user `email` field is omitted when it is null. Other resource shapes are:

```json
// Team
{"id":"01J...","slug":"acme","name":"Acme","status":"active","created_at":"2026-01-01T00:00:00Z"}

// Group
{"id":"01J...","team_id":"01J...","name":"backend"}

// Membership
{"team_id":"01J...","group_id":"01J...","user_id":"01J...","expires_at":"2026-02-01T00:00:00Z"}

// Permission
{"key":"orders:read:team","description":"Read orders","registered_by":"orders-service","created_at":"2026-01-01T00:00:00Z"}

// Role (platform roles omit team_id)
{"id":"01J...","team_id":"01J...","name":"operator"}

// Role binding
{"id":"01J...","team_id":"01J...","role_id":"01J...","subject_kind":"user","subject_id":"01J...","condition":"resource.team_id == subject.team_id","expires_at":"2026-02-01T00:00:00Z"}

// Audit entry
{"id":1,"team_id":"01J...","actor_id":"01J...","action":"user.created","target":"01J...","diff":{},"request_id":"req...","at":"2026-01-01T00:00:00Z"}
```

Nullable fields with `omitempty` (`team_id`, `condition`, `expires_at`, and
nullable audit identifiers) are absent rather than emitted as JSON null.
`client_meta` on a session is an opaque JSON object, but sessions are not
returned by an HTTP route.

Collection endpoints return a cursor page:

```json
{"items":[/* resource objects */],"next_cursor":"01J..."}
```

`next_cursor` is an empty string when there is no next page. Audit pages use an
integer cursor and return `0` when there is no next page. `limit` defaults to
100, is required to be positive when supplied, and is capped by the store at
1000.

## Problem responses

Errors use `Content-Type: application/problem+json` and RFC 9457 fields:

```json
{
  "type": "about:blank",
  "title": "Invalid Request",
  "status": 400,
  "detail": "request body must be valid JSON",
  "instance": "request-id"
}
```

`detail` and `instance` may be omitted when empty. `instance` is the request ID
created by the HTTP middleware. Common statuses are 400 (malformed or invalid
request), 401 (missing/invalid/stale authentication), 404 (missing resource),
409 (unique constraint conflict), 422 (invalid permission or condition), 429
(authentication rate limit), and 500 (service/database failure). Error details
are intentionally generic for authentication and database failures.

## Runtime plane

### `GET /.well-known/jwks.json` — Public

Returns `200` with `Content-Type: application/jwk-set+json` and a standard JWK
set. The response has a `keys` array containing the public Ed25519 keys, each
with its `kid`, `kty`, `crv`, `alg`, `use`, and public key material. Private key
material is never returned.

### `POST /auth/login` — Public password login

Request:

```json
{"username":"alice","password":"correct horse battery staple"}
```

On an active user with a valid password, `200` returns:

```json
{
  "access_token":"<JWT>",
  "refresh_token":"<opaque token>",
  "token_type":"Bearer",
  "expires_in":600
}
```

Invalid credentials and malformed login bodies return `401` with a problem;
rate-limit exhaustion returns `429`.

### `POST /auth/client-credentials` — Public service login

Request:

```json
{"client_id":"orders-service","client_secret":"<service secret>"}
```

The response is the same token response as password login, with an access JWT
whose `kind` is `service`. The user must have a credential row whose `kind` is
`service`; create one through the authenticated credential administration route
below.

### `POST /auth/refresh` — Public refresh rotation

Request:

```json
{"refresh_token":"<opaque refresh token>"}
```

A valid, unexpired refresh token returns a new token response (`200`). The
presented token is revoked as `rotated`. An expired, unknown, or reused token
returns `401`; reuse also revokes every token in that refresh family.

### `POST /auth/logout` — Public refresh-family logout

Request:

```json
{"refresh_token":"<opaque refresh token>"}
```

The token's refresh family is revoked and `204 No Content` is returned. Missing,
empty, or unknown refresh tokens are also treated as an idempotent `204`. A
malformed body is likewise treated as no token. Logout does not revoke an
already-issued access JWT; see [revocation semantics](operations.md#revocation-semantics).

### `POST /auth/introspect` — Service-only

The caller must send a valid service access token in `Authorization`. The body
contains either an access JWT or a refresh token:

```json
{"token":"<access-or-refresh-token>"}
```

The endpoint returns `200` for both active and inactive tokens. An inactive or
missing token is represented by `{ "active": false }`. An active access token
returns:

```json
{"active":true,"sub":"01J...","team":"01J...","kind":"user","perm_ver":3,"exp":1760000000}
```

An active refresh token returns the same fields based on its session and user.
`team` is omitted when empty; `sub`, `team`, `kind`, `perm_ver`, and `exp` are
omitted for inactive responses. Invalid service authentication returns `401`.

## Runtime authorization plane

### `POST /authz/check` — Service-only

Request:

```json
{
  "subject":"01J-user",
  "permission":"orders:read:team",
  "context":{
    "resource":{
      "owner_id":"01J-owner",
      "team_id":"01J-team",
      "attrs":{"region":"us-east-1"}
    }
  }
}
```

`context.resource.attrs` is an arbitrary JSON object. The response is `200`:

```json
{"allow":true,"matched":["orders:read:team"],"reason":"permission granted"}
```

`matched` is an array of permission keys. `reason` is one of `permission
 granted`, `no matching grant`, `condition denied`, `permission denied`, or
`user disabled` as applicable. A missing user is `404`; an invalid permission
grammar is `422`; malformed JSON or a missing subject is `400`; invalid service
authentication is `401`. Authorization is fail-closed when conditions fail.
Deny rows are not enabled in the current v1 resolver.

### `GET /authz/permissions/{userID}` — Service-only

Returns the effective set used by SDK caches:

```json
{
  "user_id":"01J-user",
  "perm_ver":3,
  "grants":[
    {"key":"orders:read:team"},
    {"key":"orders:update:own","condition":"resource.owner_id == subject.id"}
  ]
}
```

`condition` is omitted for an unconditional grant. A missing user is `404`, an
invalid service token is `401`, and resolver/database failures are `500`.

## Admin plane

Every route in this section requires an `admin-subject`: an active bearer
access token whose subject and `perm_ver` pass the shared authentication
middleware. Both `user` and `service` token kinds satisfy the current subject
check. There is no unauthenticated first-user route and no `iam:*` permission
gate in the current implementation.

Collection list and create methods are registered with both `/collection` and
`/collection/`; the item paths below use the canonical slashless form.

### Users

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /users?cursor=&limit=` | No body. | `200` page of `User`. |
| `POST /users` | `{"username":"alice","email":"alice@example.test","display_name":"Alice","password":"..."}`. `password` and `initial_password` are accepted; `password` wins when both are present. Both are optional. | `201` created `User`. |
| `GET /users/{id}` | No body. | `200` `User`. |
| `PATCH /users/{id}` | Any of `username`, `email`, `display_name`, `status`; `status` is `active` or `disabled`. | `200` updated `User`. |
| `DELETE /users/{id}` | No body. | `204`. |
| `POST /users/{id}/disable` | No body. | `200` disabled `User`. |
| `POST /users/{id}/credentials` | `{"kind":"service"}` generates a service secret, or `{"kind":"password","password":"..."}` creates/rotates a password credential. | `201` `{"user_id":"01J...","username":"orders-service","kind":"password"}`; service credentials additionally return `client_id` (the username) and one-time `client_secret`. |

The credential endpoint accepts only `kind` `service` or `password`. A service
credential's generated `client_secret` is returned only on creation/rotation
and must be stored immediately. Password hashes never appear in responses.
Creating a user with a password creates a `password` credential. Deleting or
disabling a user affects related sessions and permissions as described in the
operations runbook.

Invalid `kind` or a missing password for `kind=password` returns `400`; an
unknown user returns `404`; and a missing or stale admin bearer returns `401`.

### Teams

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /teams?cursor=&limit=` | No body. | `200` page of `Team`. |
| `POST /teams` | `{"slug":"acme","name":"Acme","status":"active"}`; `status` defaults to `active`. | `201` created `Team`. |
| `GET /teams/{id}` | No body. | `200` `Team`. |
| `PATCH /teams/{id}` | Any of `slug`, `name`, `status`; status is `active` or `disabled`. | `200` updated `Team`. |
| `DELETE /teams/{id}` | No body. | `204`. |

### Groups and memberships

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /groups?team_id={teamID}&cursor=&limit=` | No body; `team_id` is required. | `200` page of `Group`. |
| `POST /groups` | `{"team_id":"01J-team","name":"backend"}`. | `201` created `Group`. |
| `GET /groups/{id}` | No body. | `200` `Group`. |
| `PATCH /groups/{id}` | Any of `team_id`, `name`. | `200` updated `Group`. |
| `DELETE /groups/{id}` | No body. | `204`. |
| `PUT /groups/{id}/members` | `{"user_id":"01J-user","expires_at":"2026-02-01T00:00:00Z"}`; `expires_at` is optional. | `200` `Membership`. |
| `DELETE /groups/{id}/members` | `{"user_id":"01J-user"}`. | `204`. |
| `DELETE /groups/{id}/members/{userID}` | No body. | `204`. |

### Roles

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /roles?team_id={teamID}&cursor=&limit=` | No body; `team_id` is optional (`null` scope is platform-wide). | `200` page of `Role`. |
| `POST /roles` | `{"team_id":"01J-team","name":"operator"}`. `team_id` may be a string or JSON `null`. | `201` created `Role`. |
| `GET /roles/{id}` | No body. | `200` `Role`. |
| `PATCH /roles/{id}` | Any of `team_id` (string or null), `name`. | `200` updated `Role`. |
| `DELETE /roles/{id}` | No body. | `204`. |
| `PUT /roles/{id}/permissions` | `{"permission_keys":["orders:read:team"]}`. The legacy field `permissions` is also accepted when `permission_keys` is absent. | `200` `{"role_id":"01J...","permissions":["orders:read:team"]}`. |

### Permissions

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /permissions?cursor=&limit=` | No body. | `200` page of `Permission`. |
| `POST /permissions` | `{"key":"orders:read:team","description":"Read orders","registered_by":"orders-service"}`. | `201` upserted `Permission`. |

Permission keys are validated as `resource:action:scope`; invalid keys return
`422`. Registration bumps the global permission registry epoch.

### Role bindings

| Method and path | Request | Response |
| --- | --- | --- |
| `GET /bindings?subject_kind=user&subject_id={id}&cursor=&limit=` | No body. Both query values are required; `subject_kind` is `user` or `group`. | `200` page of `RoleBinding`. |
| `POST /bindings` | `{"team_id":"01J-team","role_id":"01J-role","subject_kind":"user","subject_id":"01J-user","condition":"resource.team_id == subject.team_id","expires_at":"2026-02-01T00:00:00Z"}`. `team_id`, `condition`, and `expires_at` are optional. | `201` created `RoleBinding`. |
| `DELETE /bindings/{id}` | No body. | `204`. |

Conditions are compiled and validated when a binding is created. A condition
that cannot be evaluated at check time fails closed.

### Audit log

`GET /audit?team_id={teamID}&cursor=0&limit=100` returns `200` with:

```json
{"items":[{"id":1,"team_id":"01J...","actor_id":"01J...","action":"user.created","target":"01J...","diff":{},"request_id":"req...","at":"2026-01-01T00:00:00Z"}],"next_cursor":0}
```

`team_id` is optional. `cursor` must be a non-negative integer. The audit log
is append-only by contract; this API exposes no update or delete method.
