# Operations runbook

This service is intended to run behind Nekostick on a private HTTP boundary.
PostgreSQL is the system of record; signing keys are separate state that must be
protected and shared by every replica.

## Configuration checklist

Configuration is loaded with the precedence **CLI flag > environment variable >
default**. The supported environment variables are:

| Variable | Default | Purpose |
| --- | --- | --- |
| `TEAMUSERS_CONNECTION_STRING` | empty | PostgreSQL DSN; required by `run` and `doctor`. |
| `TEAMUSERS_LISTEN_ADDRESS` | `127.0.0.1` | HTTP bind address. |
| `TEAMUSERS_LISTEN_PORT` | `0` | HTTP port; `0` asks the OS for an ephemeral port. |
| `TEAMUSERS_NODE_ID` | empty | Optional node label for deployment metadata. |
| `TEAMUSERS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TEAMUSERS_KEY_DIR` | `./data/keys` | Ed25519 private/public keys and the `ACTIVE` marker. |
| `TEAMUSERS_NATS_URL` | empty | NATS URL for the JetStream outbox relay. |
| `TEAMUSERS_NOTIFICATION_ENDPOINTS` | empty | Comma-separated notification service endpoint URLs. |
| `TEAMUSERS_NOTIFICATION_SECRET` | empty | HMAC-SHA256 signing secret for notification service calls. |
| `TEAMUSERS_REGISTRATION_MODE` | `closed` | Public registration mode: `closed`, `approval`, or `open`. |
| `TEAMUSERS_LOCKOUT_THRESHOLD` | `5` | Failed password or MFA attempts before lockout. |
| `TEAMUSERS_LOCKOUT_DURATION` | `15m` | Duration of an account lockout; parsed by `time.ParseDuration`. |
| `TEAMUSERS_PASSWORD_MIN_LENGTH` | `12` | Minimum Unicode password length; passwords also require a letter and digit. |

Do not put credentials in the repository. Use Nekostick's protected service
configuration or another approved secret facility, and restrict read access.

## First run

1. Create a PostgreSQL 16 database and a deployment role. The role needs the
   permissions required to run the embedded migrations. Keep the DSN in
   `TEAMUSERS_CONNECTION_STRING`; do not put it on a command line that is visible
   to other users.
2. Create the key directory with owner and mode suitable for the service. On a
   fresh directory, startup generates an Ed25519 key, writes the public JWK and
   `ACTIVE`, and logs a warning (`no signing keys found; generated an EdDSA
   signing key`). Treat that warning as a bootstrap event: back up the key
   directory immediately and do not let independent replicas generate their own
   keys.
3. Start `teamusers run`. It obtains the migration advisory lock, applies
   embedded migrations, opens PostgreSQL, loads the signing keys, and starts the
   HTTP server. Migrations are safe to run concurrently because of the advisory
   lock. `GET /readyz` becomes `200 {"status":"ready"}` after the service has
   opened its database pool and can execute `SELECT 1`; it returns `503` while
   the database is unavailable. `GET /healthz` is a process liveness check and
   does not query PostgreSQL.
4. Verify the process without exposing secrets. The examples below use an
   explicitly configured local port; when `TEAMUSERS_LISTEN_PORT=0`, replace
   `127.0.0.1:8080` with the actual `address` from the `HTTP server serving`
   log record:

   ```sh
   teamusers doctor
   teamusers status
   curl -fsS http://127.0.0.1:8080/healthz
   curl -fsS http://127.0.0.1:8080/readyz
   ```

   `status` emits redacted configuration. `doctor` checks the database,
   migration version, and key-directory write access.

### Initial identities

The admin plane has no unauthenticated bootstrap endpoint. An initial admin
subject must therefore be provisioned by an approved out-of-band bootstrap
procedure (for example, a controlled database bootstrap tool) before the first
admin API request. Do not expose the admin router without an authenticated
bootstrap subject.

Once `ADMIN_ACCESS_TOKEN` is available, create the first human user through
the admin API. Set `IAM_BASE_URL` to the actual bound address (the examples use
an explicit local `8080` listener):

```sh
export IAM_BASE_URL=http://127.0.0.1:8080
export ADMIN_ACCESS_TOKEN='use-a-secret-manager-value'

curl --fail-with-body -sS -X POST "$IAM_BASE_URL/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","email":"alice@example.test","display_name":"Alice","password":"Replace-this-before-use1"}'
```

The response is the created user and never includes a password hash. The admin
API does not return credentials from `GET /users/{id}`.

Create a separate active user for each service account (omit a password here;
the credential endpoint below creates the service secret):

```sh
curl --fail-with-body -sS -X POST "$IAM_BASE_URL/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"username":"orders-service","display_name":"Orders service"}'
```

Copy the returned user's `id` into `SERVICE_USER_ID`.

Create a service credential for a dedicated service-account user, then use the
one-time secret returned by the credential endpoint for client credentials:

```sh
SERVICE_USER_ID='01J-service-user-id'

curl --fail-with-body -sS -X POST "$IAM_BASE_URL/users/$SERVICE_USER_ID/credentials" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"kind":"service"}'

curl --fail-with-body -sS -X POST "$IAM_BASE_URL/auth/client-credentials" \
  -H 'Content-Type: application/json' \
  --data '{"client_id":"orders-service","client_secret":"use-the-one-time-secret"}'
```

The service credential response contains `user_id`, `username`, `kind`,
`client_id` (the service user's username), and a generated `client_secret`.
The client secret is returned only at creation/rotation time; store it in a
protected secret facility and never put it in deployment configuration, logs,
or source control. A password credential can be created or rotated with the
same endpoint by passing `{"kind":"password","password":"..."}`; that
response contains no credential material. Use a separate active user for each
service account.

## Key rotation

All replicas must read the same protected `TEAMUSERS_KEY_DIR`. The directory uses
these files:

- `ed25519-<kid>.pem`: PKCS#8 Ed25519 private key PEM, mode `0600`.
- `ed25519-<kid>.jwk`: generated public JWK, mode `0644`.
- `ACTIVE`: one key ID, mode `0600`, naming the key used for new tokens.

A rotation with a JWKS overlap is:

1. Generate a new PKCS#8 Ed25519 private key outside the service, install it as
   `ed25519-<new-kid>.pem` on the shared key storage, and restrict it to mode
   `0600`. The `<new-kid>` value must be non-empty and unique.
2. Before restarting any instance, write the new ID to a temporary file and
   atomically rename it to `ACTIVE` (also mode `0600`). On startup the service
   loads every `ed25519-*.pem`, derives/refreshes each public JWK, and uses the
   marker for new signatures.
3. Ask Nekostick to start a new child instance with the shared key directory.
   Wait for its `/healthz` check, confirm the captured logs show the expected
   address, and fetch `/.well-known/jwks.json`; the old and new public keys
   must both be present while old access tokens may still be presented. Then
   switch forwarding to the new instance and let Nekostick drain the old one.
4. Keep the old private key and public JWK for at least twice the access-token
   TTL (20 minutes) after the last old-key signer has drained. A longer overlap
   is safer for disconnected SDKs. Then remove the old key on the shared
   storage during a maintenance window and repeat the supervised restart.

The service currently does not emit a `key.rotated` outbox row automatically;
coordinate SDK JWKS refresh through the normal JWKS cache/`kid` miss behavior.
Never copy private keys into deployment artifacts or commit them.

## Revocation semantics

The following is the contract consumers must implement:

- **Access JWTs:** TTL is 10 minutes. Logout and refresh rotation revoke the
  refresh session, not already-issued access JWTs. An access JWT is accepted
  only while its signature/expiry is valid, the user is active, and its
  `perm_ver` equals the current user row. The middleware therefore rejects a
  disabled user or a permission-version change without waiting for the JWT TTL.
- **Refresh token:** refresh tokens are opaque and stored as SHA-256 digests.
  Each token has a 30-day expiry, bounded by a 90-day absolute family cap.
  Rotation revokes the presented token. Presenting a rotated token triggers
  reuse detection and revokes the complete family. Logout revokes the complete
  family with reason `logout`.

Password changes replace the Argon2id password credential and revoke every
refresh session for that user, including the session used by the password-change
request. The response tells the caller to sign in again; an already-issued access
JWT remains subject to the normal ten-minute and active-user checks. Users can
inspect active sessions with `GET /me/sessions` and revoke one with
`DELETE /me/sessions/{id}`. Administrators can list or revoke sessions through
the corresponding `/users/{id}/sessions` endpoints. Session IDs are opaque
SHA-256 refresh-token digests and never reveal the plaintext token.

- **`perm_ver`:** mutations that affect a user's effective permissions bump the
  user's monotonic `perm_ver`; the value is copied into new access JWTs and the
  `/authz/permissions/{userID}` response. Existing access tokens with an old
  value fail authentication. `/authz/check` resolves the current database state
  and is immediate; SDK cache consumers still need to honor `perm_ver` and
  invalidation events.
- **Introspection:** access-token introspection follows the access contract
  (active user and matching `perm_ver`), while refresh-token introspection also
  checks session revocation and expiry.

These rules mean that refresh-family logout is not an instant access-token
revocation mechanism; permission changes and user disablement are enforced by
the active-user/`perm_ver` checks.

## Rate limits and password work

The limiter is in-process and bounded to 10,000 keys. Stale buckets are swept
lazily after two minutes.

- Password login: five requests per minute per normalized `(client IP,
  username)`, plus 30 requests per minute per client IP.
- Service client-credentials login: 30 requests per minute per client IP.
- Refresh, logout, and introspection: 30 requests per minute per client IP.

Argon2id verification has four concurrent slots. If all slots remain busy for
two seconds, authentication returns `429 application/problem+json` rather than
queueing unbounded password work. Rate-limit state is per process; coordinate
limits at the trusted proxy if fleet-wide limits are required.

Account lockout is stored on the user row. A failed password or MFA attempt
increments `failed_logins`; reaching `TEAMUSERS_LOCKOUT_THRESHOLD` sets
`locked_until`. While the deadline is in the future, login returns `423
account_locked` before password verification. A successful password-only login
or MFA completion resets both fields. Disabling a user through the admin API
also resets the fields. After the duration elapses, the user can try again.

## Bulk admin operations

The admin batch endpoints cap each request at 500 user IDs or CSV data rows. A
status or membership batch commits each successful row independently, so an
unknown user does not roll back other rows. An unknown group is checked before
processing membership rows and rejects the whole request. CSV imports require
the exact `username,email,display_name,password` header and create active users
without registration or email-verification side effects. Review the returned
per-row `error` values and reconcile failed rows before retrying; retries of a
successful membership row are reported as `already_member`.


TOTP enrollment is completed through `/me/totp/enroll` and
`/me/totp/confirm`. The confirmation response contains ten one-time backup
codes; operators must direct users to store them in an approved secrets
facility because the service never displays them again.

## Notification service integration

Set `TEAMUSERS_NOTIFICATION_ENDPOINTS` to a comma-separated list of notification
service endpoint URLs and `TEAMUSERS_NOTIFICATION_SECRET` to the HMAC secret
shared with the notification service. The notifier polls the notification
outbox every two seconds. It sends notification directives currently emitted by
this service (`user.created`, `user.disabled`, `user.verification`,
`user.approved`, and `session.reuse_detected`) as HMAC-signed JSON `POST`
requests to each configured endpoint. This service decides what to notify and
when; the notification service owns actual email/SMS delivery.

```json
{
  "id": 42,
  "type": "user.created",
  "data": {"user_id":"01J...","username":"alice"},
  "at": "2026-01-01T00:00:00Z"
}
```

Headers are `Content-Type: application/json` and
`X-Teamusers-Signature-256: sha256=<lowercase hex HMAC-SHA256>`. The HMAC input is
the exact raw request body, not re-serialized JSON. The notification service can verify it
before parsing:

```python
import hashlib
import hmac


def verify(raw_body: bytes, header: str, secret: bytes) -> bool:
    expected = "sha256=" + hmac.new(secret, raw_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, header)
```

Each endpoint gets an initial attempt plus three retries, with delays of 1, 4,
and 15 seconds. Requests time out after five seconds. A non-2xx response or
network failure leaves the outbox row unpublished for a later poll, so delivery
is at-least-once and the configured notification service must deduplicate by event `id`.
With no notification service endpoints configured, notification rows are
acknowledged locally in development mode. Do not use an empty endpoint list as a
production delivery guarantee.

Set `TEAMUSERS_NATS_URL` to enable the relay. It publishes recognized outbox
topics other than `notify.*` notification directives to these subjects:

| Outbox topic | JetStream subject |
| --- | --- |
| `perm.changed` | `iam.perm.changed` |
| `user.disabled` | `iam.user.disabled` |
| `role.updated` | `iam.role.updated` |
| `key.rotated` | `iam.key.rotated` |

Provision a JetStream stream covering `iam.*` before enabling the relay; the
service connects to JetStream but does not create a stream or consumer. If the
NATS URL is empty, recognized relay events are marked published in development
mode without a broker. Failed publishes remain unpublished and are retried by
the two-second poller. Consumers must deduplicate by `event_id`.

## Backups and retention

Back up PostgreSQL and the complete signing-key directory together. A database
backup without the corresponding private keys cannot validate or issue tokens
across restore boundaries; a key backup without the database cannot restore
users or sessions.

The `audit_log` is append-only by contract. Give the deployment role INSERT and
SELECT access only; do not grant UPDATE or DELETE. Preserve it in every backup
and export it to long-term immutable storage according to the organization's
retention policy.

The `outbox` is also durable state. The relay marks rows with `published_at`
after successful publication, but this service does not delete old published
rows. Define and document an operator-owned retention/archive job only after
all consumers and notification service endpoints have their required replay
window. Never purge unpublished rows merely because they are old; investigate
delivery or broker failures first.

The hourly session reaper deletes rows whose ordinary refresh TTL has elapsed;
its successful and failed counts are visible in structured logs.

## Monitoring and incident signals

- Poll `GET /healthz`: `200 {"status":"ok"}` means the HTTP process is
  serving. It intentionally does not prove database readiness.
- Poll `GET /readyz`: `200 {"status":"ready"}` means the database `SELECT 1`
  check succeeds; `503 {"status":"not_ready"}` means it does not. Alert on a
  sustained not-ready state and on restart loops.
- Run `teamusers doctor` during deployment and incident triage. Its JSON
  report separates database, migration, and key-directory checks.
- Alert on `reaped expired sessions` errors, `notification service delivery failed`,
  `notification notifier poll failed`, `outbox relay poll failed`, and repeated
  `publish outbox event failed` log records. Track pending/unpublished outbox
  rows and notification retry volume.
- Alert on a new `refresh token reuse detected` warning: it indicates a
  presented rotated token and family-wide revocation, often a stolen or
  concurrently used credential.

On `SIGTERM`, the process stops accepting new requests, drains in-flight HTTP
handlers and event workers, and exits within the ten-second application drain
budget. Nekostick sends the signal to the child process group and allows a
15-second grace period before using `SIGKILL`.

For a content-hash upgrade or restart, Nekostick starts the new service
instance first, waits for its `/healthz` check to pass, switches forwarding to
the new instance, and then drains the old one. Never route new traffic to an
instance after its drain begins; investigate a failed health check before
terminating the healthy instance.
