# HTTP API

The service listens on the address selected by `TEAMUSERS_LISTEN_ADDRESS` and
`TEAMUSERS_LISTEN_PORT`. It serves JSON over plain HTTP; TLS termination belongs
to the Nekostick/reverse-proxy boundary. The paths below are root-relative;
publish the service under a custom prefix such as `/iam/` with Nekostick's
default `Strip` forwarding mode, which removes the prefix before forwarding.

## Authentication classes

| Class | Meaning |
| --- | --- |
| Public | No bearer token is required. |
| User bearer | `Authorization: Bearer <access-token>` for an active user or service subject. The token's `perm_ver` must still match the user row. `/me` requires a `kind=user` token and always acts on that token subject. |
| Service-only | A valid active access token whose JWT `kind` claim is `service`. |
| Admin-subject | A valid active bearer whose JWT `kind` is `user`; each route family additionally requires its `iam:*` permission key. Service subjects are rejected with `403`. |

Access tokens are EdDSA JWTs. The issuer is `teamusers`; the claims include
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
`client_meta` on a session is retained internally. Session endpoints expose only
the opaque digest ID and `created_at`/`expires_at` timestamps.

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
409 (unique or TOTP enrollment conflict), 422 (invalid permission, condition,
or password policy), 423 (account lockout), 429 (authentication rate limit),
and 500 (service/database failure). Error details are intentionally generic for
authentication and database failures.

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
rate-limit exhaustion returns `429`. An account whose `locked_until` is in the
future returns `423` with problem detail `account_locked` before password work.

When the active user has a confirmed TOTP credential, valid password login
returns `200` with a short-lived challenge instead of tokens:

```json
{"mfa_required":true,"mfa_token":"<EdDSA JWT>"}
```

The MFA token expires after five minutes and is accepted only by the MFA login
endpoint below.

### `POST /auth/login/mfa` — Public MFA completion

Submit the challenge token and either the current six-digit TOTP code or one of
the one-time backup codes:

```json
{"mfa_token":"<JWT>","code":"123456"}
```

A valid code returns the normal access and refresh token pair. A backup code is
deleted atomically when used; replaying it returns `401`. Invalid MFA codes
count toward the account lockout threshold and requests are rate-limited per IP.

### `POST /auth/password-reset/request` — Public password-reset request

Submit either a username or an email address:

```json
{"login":"alice@example.test"}
```

The endpoint always returns `204 No Content` with an empty body, whether the
login exists, is inactive, or is unknown. This anti-enumeration behavior also
applies when no reset token is issued. An active matching user receives a
transactional `notify.password.reset_requested` outbox event containing the
plaintext one-time token for delivery; the token itself is never returned by
HTTP. Requests are rate-limited by client IP and normalized login string.

### `POST /auth/password-reset/confirm` — Public password-reset confirmation

Submit the token delivered by the notification service and a replacement
password:

```json
{"token":"<one-time-token>","new_password":"new-password2"}
```

An unexpired, unused token is consumed atomically. The replacement must satisfy
the configured password policy or the endpoint returns `422` with
`weak_password`; unknown, expired, used, or wrong-kind tokens return `400` with
`invalid_token`. Success returns `204`, replaces or creates the password
credential, revokes every refresh session, clears lockout state, and appends a
`password.reset_completed` audit record. Token guessing is rate-limited per IP.

### `POST /auth/register` — Public self-registration

Registration is controlled by `TEAMUSERS_REGISTRATION_MODE`. In `closed` mode
the endpoint returns `403` with a problem whose detail is
`registration_closed`. In `approval` or `open` mode, submit:

```json
{"username":"alice","email":"alice@example.test","password":"at-least-twelve1","display_name":"Alice"}
```

The username must be unique, the email must be a valid address, and the
password must be at least 12 Unicode characters containing at least one letter
and one digit. A successful request returns `201` with `{"id":"01J...","status":"pending"}`.
The password is stored only as an Argon2id credential. The service writes a
transactional `notify.user.verification` event containing the plaintext
verification token; the token is not returned by this endpoint.

### `GET /me` — User bearer self-service

The caller must send an active user access token. The response contains only the
caller's profile fields:

```json
{
  "id":"01J-user",
  "username":"alice",
  "email":"alice@example.test",
  "display_name":"Alice",
  "status":"active",
  "email_verified_at":"2026-01-01T00:00:00Z",
  "created_at":"2026-01-01T00:00:00Z"
}
```

Credential and password data are never returned. `PATCH /me` accepts only
`{"display_name":"New name"}` and returns the updated profile. Email changes
are outside this API and return `422` with an unsupported-field problem.

### `POST /me/password` — Change the own password

Submit the current and replacement passwords:

```json
{"current_password":"old-password1","new_password":"new-password2"}
```

The current password must match or the endpoint returns `401` with detail
`invalid_credentials`. The replacement must satisfy the configured password
policy or the endpoint returns `422` with detail `weak_password`. A successful
change returns `200` and explicitly states that all refresh sessions were
revoked; the caller must sign in again. This includes the session used for the
request.

### `GET /me/sessions` — List own active sessions

Returns active, unexpired refresh sessions as an array. Session IDs are opaque
SHA-256 refresh-token digests:

```json
[{"id":"<opaque-digest>","created_at":"2026-01-01T00:00:00Z","expires_at":"2026-01-31T00:00:00Z"}]
```


`DELETE /me/sessions/{id}` revokes one of the caller's sessions and returns
`204`. An unknown, revoked, expired, or foreign session ID returns `404` without
revealing whether another user's session exists.

### `POST /me/totp/enroll` — User bearer self-service

The caller must send an active user access token. Enrollment creates a pending
TOTP secret and returns it once:

```json
{"secret":"JBSWY3DPEHPK3PXP...","otpauth_url":"otpauth://totp/teamusers:alice?secret=...&issuer=teamusers"}
```

An active TOTP credential causes `409` with problem detail
`totp_already_enabled`. The pending secret is stored in the credentials table
until confirmation.

### `POST /me/totp/confirm` — Confirm TOTP enrollment

Submit the current code from the pending secret:

```json
{"code":"123456"}
```

On success the pending credential becomes active and ten 16-character lowercase
alphanumeric backup codes are returned in `xxxx-xxxx-xxxx-xxxx` display form
under `backup_codes`. Codes are returned only in this response; the canonical
no-dash lowercase values are stored as SHA-256 digests in one JSON credential.

### `POST /me/totp/backup-codes` — Regenerate backup codes

The caller must send an active user bearer token and the current password:

```json
{"password":"current-password1"}
```

An active TOTP credential is required; otherwise the endpoint returns `404`
with `mfa_not_enrolled`. A wrong password returns `401` with
`invalid_credentials`. Success returns `200` with ten newly generated
`xxxx-xxxx-xxxx-xxxx` codes. The old backup-code set is replaced atomically,
and the plaintext codes are returned only in this response. The operation is
audited as `mfa.backup_codes_regenerated`.

### `DELETE /me/totp` — Disable TOTP

Submit a valid TOTP or backup code. The active TOTP and all backup credentials
are deleted, and the endpoint returns `204 No Content`.

### `POST /me/passkeys/register/begin` — Begin passkey registration

The caller must send an active user bearer token. The request body is empty. The
response is the WebAuthn credential-creation options object; the `publicKey`
member includes the RP (`rp.id = "localhost"` by default), user handle, a
base64url challenge, and `attestation = "none"`:

```json
{
  "publicKey": {
    "rp": {"name":"teamusers","id":"localhost"},
    "user": {"name":"alice","displayName":"Alice","id":"..."},
    "challenge":"<base64url>",
    "pubKeyCredParams":[{"type":"public-key","alg":-7}],
    "attestation":"none"
  }
}
```

The server stores the ceremony session for five minutes. `POST
/me/passkeys/register/finish` accepts the browser's standard
`PublicKeyCredential` creation response and returns `204` after the credential
is stored. A challenge is single-use; malformed, expired, or replayed
responses return a problem response.

### `GET /me/passkeys` and `DELETE /me/passkeys/{credID}` — Manage passkeys

`GET /me/passkeys` returns only credential identifiers and their enrollment
timestamp; public-key and attestation material is never returned:

```json
[{"id":"<base64url credential id>","created_at":"2026-01-01T00:00:00Z"}]
```

`DELETE /me/passkeys/{credID}` uses the same unpadded base64url identifier and
returns `204`. An unknown identifier returns `404` without revealing another
credential.

### `POST /auth/passkey/login/begin` — Begin passkey login

This public endpoint accepts an optional username. The body may be omitted or
an empty object to start a discoverable ceremony:

```json
{"username":"alice"}
```

The response is the WebAuthn credential-request options object with a five-minute,
single-use challenge. An unknown username and an account without passkeys
return the same generic authentication problem.

### `POST /auth/passkey/login/finish` — Finish passkey login

Submit the browser's standard `PublicKeyCredential` assertion response. A
successful assertion returns the normal full token pair:

```json
{"access_token":"<JWT>","refresh_token":"<opaque token>","token_type":"Bearer","expires_in":600}
```

The active-user and account-lockout checks are the same as password login;
failed assertions count toward the configured lockout threshold.

### `POST /auth/verify-email` — Public email verification

Submit the token delivered through the notification service:

```json
{"token":"<base64url verification token>"}
```

An unexpired, unused token returns `204 No Content` and records
`email_verified_at`. In `open` mode the pending user also becomes active. In
`approval` mode the user remains pending until an administrator approves it.
Email verification is mode-independent; in `closed` and `approval` modes it
records verification but never activates an account.
An unknown, expired, already-used, or otherwise invalid token returns `400`
with problem detail `invalid_token`.

Pending accounts have their password checked normally but `/auth/login` then
returns `403` with problem detail `account_pending`; invalid credentials still
return the generic `401` authentication problem.

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
middleware, whose JWT `kind` is `user`, and whose effective permissions include
the key for the route family. Permission resolution runs against the current
database state on every admin request.

| Route family | Required permission |
| --- | --- |
| `/users*` (except `/users/{id}/sessions*`) | `iam:users:any` |
| `/teams*` | `iam:teams:any` |
| `/groups*` | `iam:groups:any` |
| `/roles*` | `iam:roles:any` |
| `/permissions` | `iam:permissions:any` |
| `/bindings*` | `iam:bindings:any` |
| `/audit` | `iam:audit:any` |
| `/users/{id}/sessions*` | `iam:sessions:any` |

Missing keys return `403` with problem detail `insufficient_permissions`.
Service-kind tokens are also rejected with `403` before permission resolution.
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
| `POST /users/batch` | `{"ids":["01J..."],"op":"disable"}` or `op` `enable`; up to 500 IDs. | `200` `{"results":[{"id":"01J...","ok":true},{"id":"missing","ok":false,"error":"not_found"}]}`. Each row is independent; unknown IDs are row errors. Disable rows use the same session revocation, lockout reset, permission invalidation, audit, and notification transition as the single-user operation. |
| `POST /users/import` | `text/csv` with header `username,email,display_name,password`; up to 500 data rows. | `200` `{"results":[{"row":2,"username":"alice","ok":true,"id":"01J..."},{"row":3,"username":"bob","ok":false,"error":"weak_password"}]}`. Rows are numbered from the CSV file (the header is row 1). Users are active immediately and receive password credentials; malformed CSV or a missing/invalid header returns `422`. |
| `POST /users/{id}/credentials` | `{"kind":"service"}` generates a service secret, or `{"kind":"password","password":"..."}` creates/rotates a password credential. | `201` `{"user_id":"01J...","username":"orders-service","kind":"password"}`; service credentials additionally return `client_id` (the username) and one-time `client_secret`. |
| `DELETE /users/{id}/totp` | No body. | `204`; deletes active/pending TOTP and backup-code credentials and appends `admin.totp_reset`. Unknown users return `404`. |
| `POST /users/{id}/approve` | No body. | `200` active `User`; emits `notify.user.approved`. |
| `GET /users/{id}/sessions` | No body. | `200` active sessions as `[{"id":"<opaque-digest>","created_at":"...","expires_at":"..."}]`. |
| `DELETE /users/{id}/sessions/{sid}` | No body. | `204`; only the session belonging to `{id}` is affected. |
| `DELETE /users/{id}/sessions` | No body. | `204`; revokes all refresh sessions for the user. |

All three session operations are audited. Unknown users and unknown or
foreign session IDs return `404` without disclosing session ownership.

The credential endpoint accepts only `kind` `service` or `password`. A service
credential's generated `client_secret` is returned only on creation/rotation
and must be stored immediately. Password hashes never appear in responses.
Creating a user with a password creates a `password` credential. Deleting or
disabling a user affects related sessions and permissions as described in the
operations runbook.

Invalid `kind` or a missing password for `kind=password` returns `400`; an
unknown user returns `404`; and a missing or stale admin bearer returns `401`.

In `approval` registration mode, approval requires `email_verified_at` and
returns `422` with problem detail `email_not_verified` when verification has
not completed. An unknown user returns `404`.

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
| `POST /groups/{id}/members/batch` | `{"user_ids":["01J-user", "01J-other"]}`; up to 500 IDs. | `200` `{"results":[{"id":"01J-user","ok":true},{"id":"01J-other","ok":false,"error":"already_member"}]}`. Duplicate or unknown users are row errors; an unknown group returns `404` for the whole request. Successful rows bump each affected user's `perm_ver` and append `membership.created` audit entries. |
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
