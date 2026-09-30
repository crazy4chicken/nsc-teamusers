---
title: Operations runbook
outline: 2
---

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
| `TEAMUSERS_TRUSTED_PROXIES` | empty | Comma-separated trusted proxy CIDRs or IPs; forwarded hops are walked right-to-left to select the rightmost non-trusted address. The trusted edge proxy must overwrite client-supplied `X-Forwarded-For` before forwarding. |
| `TEAMUSERS_NODE_ID` | empty | Optional node label for deployment metadata. |
| `TEAMUSERS_LOG_LEVEL` | `info` | `debug`, `info`, `warn`, or `error`. |
| `TEAMUSERS_KEY_DIR` | `./data/keys` | Ed25519 private/public keys and the `ACTIVE` marker. |
| `TEAMUSERS_NATS_URL` | empty | NATS URL for the JetStream outbox relay. |
| `TEAMUSERS_NOTIFICATION_ENDPOINTS` | empty | Comma-separated notification service endpoint URLs. |
| `TEAMUSERS_NOTIFICATION_SECRET` | empty | HMAC-SHA256 signing secret for notification service calls. |
| `TEAMUSERS_AUDIT_RETENTION_DAYS` | `0` | Whole-day audit retention window (`--audit-retention-days`); `0` keeps rows forever. |
| `TEAMUSERS_LOGIN_ACTIVITY_RETENTION_DAYS` | `90` | Whole-day login-activity retention window; `0` disables deletion. |
| `TEAMUSERS_AUDIT_FORWARD_ENDPOINTS` | empty | Comma-separated HTTP endpoints for asynchronous HMAC-signed audit-row delivery; empty disables forwarding. |
| `TEAMUSERS_AUDIT_FORWARD_SECRET` | empty | HMAC-SHA256 signing secret; required when audit-forward endpoints are configured and redacted from status output. |
| `TEAMUSERS_REGISTRATION_MODE` | `closed` | Public registration mode: `closed`, `approval`, or `open`. |
| `TEAMUSERS_OIDC_ISSUER` | empty | OpenID Provider issuer URL (`--oidc-issuer`); empty disables inbound OIDC. |
| `TEAMUSERS_OIDC_CLIENT_ID` | empty | OIDC client identifier (`--oidc-client-id`). |
| `TEAMUSERS_OIDC_CLIENT_SECRET` | empty | Confidential OIDC client secret (`--oidc-client-secret`); redacted from diagnostic output. |
| `TEAMUSERS_OIDC_REDIRECT_URL` | empty | Absolute OIDC callback URL (`--oidc-redirect-url`). |
| `TEAMUSERS_OIDC_TRUST_UPSTREAM_MFA` | `false` | Opts in to satisfying local MFA policy from recognized upstream OIDC `amr` or configured exact `acr` evidence; default false always requires local MFA when policy demands it. |
| `TEAMUSERS_OIDC_MFA_ACR_VALUES` | empty | Comma-separated exact-match `acr` values trusted only when upstream OIDC MFA trust is enabled; values are not delimiter-split. |
| `TEAMUSERS_ACCESS_TOKEN_TTL` | `10m` | Access-token lifetime (`--access-token-ttl`); parsed by `time.ParseDuration`. |
| `TEAMUSERS_REFRESH_TOKEN_TTL` | `720h` | Refresh-token lifetime (`--refresh-token-ttl`); parsed by `time.ParseDuration`. |
| `TEAMUSERS_SESSION_FAMILY_TTL` | `2160h` | Absolute session-family lifetime (`--session-family-ttl`); parsed by `time.ParseDuration` and must be at least the refresh-token TTL. |
| `TEAMUSERS_LOCKOUT_THRESHOLD` | `5` | Failed password or MFA attempts before lockout. |
| `TEAMUSERS_LOCKOUT_DURATION` | `15m` | Duration of an account lockout; parsed by `time.ParseDuration`. |
| `TEAMUSERS_PWNED_PASSWORDS_ENABLED` | `false` | Enables HIBP screening for password policies with `breach_check: true` (`--pwned-passwords-enabled`). |
| `TEAMUSERS_WEBAUTHN_RP_ID` | `localhost` | WebAuthn relying-party ID. |
| `TEAMUSERS_WEBAUTHN_ORIGIN` | `http://localhost` | WebAuthn browser origin. |

Configure all four OIDC endpoint/client values together; the service rejects partial configuration. Use HTTPS issuer and callback URLs in production. The `__Host-` state cookie is always `Secure`, so public HTTPS must terminate at the trusted reverse proxy. Upstream MFA trust is opt-in; keep `TEAMUSERS_OIDC_TRUST_UPSTREAM_MFA=false` unless relying on upstream MFA, and list permitted full `acr` values in `TEAMUSERS_OIDC_MFA_ACR_VALUES`.

Do not put credentials in the repository. Use Nekostick's protected service
configuration or another approved secret facility, and restrict read access.

For production, set both WebAuthn variables to the public relying-party
configuration: `TEAMUSERS_WEBAUTHN_RP_ID` must be the effective public domain and
`TEAMUSERS_WEBAUTHN_ORIGIN` must be the complete HTTPS origin (including the
port when it is non-default). Do not leave the localhost defaults enabled on a
public deployment; the origin is verified during every ceremony.

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

The admin plane has no unauthenticated bootstrap endpoint. Instead, startup
performs an automatic bootstrap: when no user holds a platform administrative
permission and no user named `admin` exists, the service creates an `admin`
user with a random temporary password and prints it to stdout:

```text
bootstrap: created the initial admin account
bootstrap:   username: admin
bootstrap:   temporary password: xk7Qp2…
bootstrap: the password must be changed on first login
```

Capture the password from the service log and rotate it immediately; the
credential is marked `must_change`, so the first login returns `403
password_change_required` and expects the change through `POST /me/password`
with the supplied `password_change` token. On a replica fleet, exactly one
instance wins the bootstrap race; concurrent losers detect the now-existing
`admin` user and skip. The check reruns on every restart, so deleting every
platform administrator brings the automatic bootstrap back.

To grant platform administration to a specific existing user instead, use the
idempotent store-direct CLI command:

```sh
export TEAMUSERS_CONNECTION_STRING='postgres://...'
teamusers bootstrap-admin --username alice
```

The command ensures the ten enumerated `iam:<area>:any` permission keys and
the `iam:*:any` wildcard, the platform-scoped `iam-admin` role, and the user
binding. It fails with a clear error when the username does not exist and is
safe to rerun. `iam:*:any` is a platform wildcard covering current and future
IAM areas at the `:any` scope. It does not create users or grant administrative
access at runtime.

On each normal service startup, permission reconciliation registers missing
keys and restores missing grants on the existing `iam-admin` role, keeping
upgraded deployments working.

An administrator can remove their own last `iam:*:any` grant, for example by deleting their own role binding. If that happens, recover access by rerunning `teamusers bootstrap-admin --username <name>`; the idempotent command restores the platform administrator role, permissions, and binding.

Once `ADMIN_ACCESS_TOKEN` is available, use the admin API to create additional
human users and service accounts. Set `IAM_BASE_URL` to the actual bound
address (the examples use an explicit local `8080` listener):

```sh
export IAM_BASE_URL=http://127.0.0.1:8080
export ADMIN_ACCESS_TOKEN='use-a-secret-manager-value'

curl --fail-with-body -sS -X POST "$IAM_BASE_URL/users" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"username":"bob","email":"bob@example.test","display_name":"Bob","password":"Replace-this-before-use1"}'
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

All replicas must use the same protected `TEAMUSERS_KEY_DIR`. The directory uses
these files:

- `ed25519-<kid>.pem`: PKCS#8 Ed25519 private key PEM, mode `0600`.
- `ed25519-<kid>.jwk`: generated public JWK, mode `0644`.
- `ed25519-<kid>.retire`: retired-key deadline in UTC RFC 3339 format, mode `0600`.
- `ACTIVE`: one key ID, mode `0600`, naming the key used for new tokens.

Rotate keys at runtime with `POST /keys/rotate`. The authenticated user
must have `iam:keys:any`; no request body is required. Include an
`Idempotency-Key` to make a retry return the original response:

```sh
curl --fail-with-body -sS -X POST "$IAM_BASE_URL/keys/rotate" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H "Idempotency-Key: $CHANGE_ID"
```

The response contains the new `kid` and the previous key's `retire_at`. The
service first persists the new private key and public JWK, then commits the
audit and `key.rotated` outbox rows in one transaction. Only after that commit
does it persist the previous key's retirement time and new `ACTIVE` marker,
then swap the in-memory signer. New tokens use the new key after activation;
the previous public key remains in JWKS until `retire_at`. The retirement
window is twice the maximum of the configured access-token lifetime
(`TEAMUSERS_ACCESS_TOKEN_TTL`) and the fixed MFA (5-minute) and password-change
(10-minute) token lifetimes, which is 20 minutes with the default 10-minute
access-token TTL. After that deadline the key is omitted from JWKS; the private
key, public JWK, and retirement metadata remain on disk. The relay publishes
`iam.key.rotated`; its JSON payload includes the new `kid`, rotation `at`, and
the standard outbox event fields so SDKs can refresh JWKS immediately; key-miss
refresh remains a fallback. If post-commit activation fails, the operation
still returns HTTP 200 with a `warning` field, logs the failure, and retains
the prepared key files because the database transaction has committed.

The default single-child deployment needs no restart. In a multi-replica
deployment, the in-memory swap affects only the replica handling the request.
Send one rotation request to one replica, keep application and JWKS traffic on
that replica while rolling-restarting the others, and route traffic broadly
after every replica has reloaded the shared key directory. Do not POST once per
replica: each request generates another key, while already-running peers keep
their prior in-memory JWKS. After the reload, all replicas publish the same
overlap, so old tokens continue to verify until `retire_at`.

Never copy private keys into deployment artifacts or commit them.

## Revocation semantics

The following is the contract consumers must implement:

- **Access JWTs:** the default TTL is 10 minutes, configurable with
  `TEAMUSERS_ACCESS_TOKEN_TTL` (`--access-token-ttl`). Logout and refresh
  rotation revoke the refresh session, not already-issued access JWTs. An
  access JWT is accepted only while its signature/expiry is valid, the user is
  active, and its `perm_ver` equals the current user row. The middleware
  therefore rejects a disabled user or a permission-version change without
  waiting for the configured JWT TTL.
- **Refresh token:** refresh tokens are opaque and stored as SHA-256 digests.
  Each token defaults to a 30-day expiry, configured with
  `TEAMUSERS_REFRESH_TOKEN_TTL` (`--refresh-token-ttl`), bounded by a 90-day
  default absolute family cap configured with `TEAMUSERS_SESSION_FAMILY_TTL`
  (`--session-family-ttl`). Rotation revokes the presented token. Presenting a
  rotated token triggers reuse detection and revokes the complete family.
  Logout revokes the complete family with reason `logout`.

Password changes replace the Argon2id password credential and revoke every
refresh session for that user, including the session used by the password-change
request. Administrator-provisioned password credentials are marked
`must_change`; the first valid password login returns
`403 password_change_required` with a fixed ten-minute `password_change` token
rather than tokens for API access. The client must send that token as the
bearer on `POST /me/password` together with the current and replacement
passwords. Only that endpoint and
`GET /me/password-policy` (policy pre-validation before the change) accept the
token.
Registration, invitation acceptance, and password-reset completion do not set
`must_change`. A successful change clears
the flag, revokes all refresh sessions, and requires a fresh login. An
already-issued access JWT remains subject to the configured access-token TTL
(10 minutes by default; `TEAMUSERS_ACCESS_TOKEN_TTL`) and active-user checks.
Users can inspect active sessions with `GET /me/sessions` and revoke one with
`DELETE /me/sessions/{id}`. Administrators can list or revoke sessions through
the corresponding `/users/{id}/sessions` endpoints.
Session IDs are opaque SHA-256 refresh-token digests and never reveal the
plaintext token.

Session policies are rows in `session_policies`, with nullable
`max_concurrent_sessions` and `idle_timeout_minutes` resolved independently by
priority for platform-default, team, group, and role targets. A concurrency
limit evicts the least recently rotated active user session(s) with
`evicted_by_policy` instead of rejecting a new login. Each rotation creates a
replacement row with a new creation time, which determines the eviction order.
Service-account sessions are exempt from user session policies.
`last_active_at` is set when the session is created and updated only after
successful refresh; idle timeout is enforced at refresh, which rejects and
revokes an idle session with `session_idle_expired`. The session-policy table
has no HTTP management endpoint in this release.

Users can inspect their own resolved login activity with
`GET /me/activity?limit=50`. Results are ordered by descending ID and contain
only rows tied to the bearer user; unknown-user attempts are retained with a
null `user_id` and are not visible through this endpoint. Continue with the
numeric `next_cursor` returned by each page (omit `cursor` or use `0` for the
first page). Activity includes timestamp, IP, user agent, method, and result,
never passwords or tokens; write failures are logged and do not block login.

```sh
curl --fail-with-body -sS -G "$IAM_BASE_URL/me/activity" \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  --data-urlencode 'limit=50'
```

`GET /me/sessions` and `/users/{id}/sessions` include `last_active_at` alongside
creation and expiration timestamps. It reflects session issuance and refresh,
not every access-token request.

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

## Idempotency keys

Every `POST` accepts an optional `Idempotency-Key` header. When supplied, the
service fingerprints the raw request body and keeps the completed status and
response for 24 hours. A retry with the same key and body replays the original
response and sets `Idempotency-Replayed: true`; reusing a key with a different
body returns `422` with detail `idempotency_conflict`. A request whose matching
key is still running returns `409` with detail `idempotency_in_progress`.

The key scope is the SHA-256 digest of the raw `Authorization` header when one
is present, otherwise the resolved client IP. Claims are cleaned up
opportunistically when keyed requests arrive. Responses larger than 64 KiB,
`429` responses, and `5xx` responses are not retained, so clients may retry
those requests with the same key.

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

## Account recovery operations

Password-reset requests are safe to expose through the public authentication
boundary: `POST /auth/password-reset/request` always returns an empty `204`,
including for unknown logins. For an active account, verify that the
notification outbox contains and eventually delivers the
`notify.password.reset_requested` event rather than attempting to read a token
from application logs. The recipient completes the reset with
`POST /auth/password-reset/confirm`; success revokes all refresh sessions, so
the user must sign in again on every device.

If a user has lost both their authenticator and all backup codes, use a separate
administrator account with `iam:users:any` to remove the MFA credentials:

```sh
curl --fail-with-body -sS -X DELETE "$IAM_BASE_URL/users/$USER_ID/totp" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN"
```

The operation returns `204`, is recorded as `admin.totp_reset`, and deletes the
active TOTP secret, any pending enrollment, and all backup-code digests. It does
not reset the password or return credential material. Confirm the user can sign
in with their password, then have them enroll TOTP again and store the new
backup codes in an approved secrets facility. An unknown user returns `404`.

## Invitation operations

Administrators with `iam:users:any` create invited users through
`POST /invitations`. The service stores no password credential until the
recipient accepts, hashes the one-time invitation token in
`verification_tokens`, and writes the plaintext token only to the transactional
`notify.user.invited` outbox payload. Invitation tokens are valid for seven
days. The notification service should deliver the token over the approved
invitation channel and must not expose it in logs.

Use `POST /invitations/{userID}/resend` when delivery fails. Resend marks any
previous unused invitation token used before creating a replacement, so only
the newest token can be accepted. Use `DELETE /invitations/{userID}` to cancel
an invitation; deletion cascades to its token and any other user records. Both
operations are audited as `invitation.resent` or `invitation.cancelled`.

The recipient submits the token and a policy-compliant password to
`POST /auth/invite/accept`. Success activates the account and treats the
invitation email as verified. Until acceptance, password login returns the
generic `403 account_pending` problem used for other non-active lifecycle
states.

## Notification service integration

Set `TEAMUSERS_NOTIFICATION_ENDPOINTS` to a comma-separated list of notification
service endpoint URLs and `TEAMUSERS_NOTIFICATION_SECRET` to the HMAC secret
shared with the notification service. The notifier polls the notification
outbox every two seconds. It sends notification directives currently emitted by
this service (`user.created`, `user.disabled`, `user.verification`,
`user.approved`, `user.invited`, `password.reset_requested`, and
`session.reuse_detected`) as HMAC-signed JSON `POST` requests to each configured
endpoint. This service decides what to notify and when; the notification service
owns actual email/SMS delivery.

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

| Outbox topic | JetStream subject | Event-specific payload |
| --- | --- | --- |
| `perm.changed` | `iam.perm.changed` | — |
| `user.disabled` | `iam.user.disabled` | — |
| `role.updated` | `iam.role.updated` | — |
| `key.rotated` | `iam.key.rotated` | — |
| `user.created` | `iam.user.created` | `{"user_id":"<user-id>","changed_fields":["username","email","display_name","status"]}` |
| `user.updated` | `iam.user.updated` | `{"user_id":"<user-id>","changed_fields":["display_name"]}` |
| `user.deleted` | `iam.user.deleted` | `{"user_id":"<user-id>"}` |
| `team.created` | `iam.team.created` | `{"team_id":"<team-id>","changed_fields":["slug","name","status"]}` |
| `team.updated` | `iam.team.updated` | `{"team_id":"<team-id>","changed_fields":["name"]}` |

Each lifecycle message also carries the relay envelope fields `event_id`, `type`,
and `at`; `user_ids` and `team_id` retain their existing envelope semantics.
`changed_fields` contains field names, not field values. Lifecycle payloads
contain no passwords, credential hashes, or other secrets. Consumers that need
current field values can fetch the entity separately.

The `user.deleted` lifecycle payload omits `changed_fields`.

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

The `audit_log` is append-only while a row is retained; application code never
updates audit rows. `TEAMUSERS_AUDIT_RETENTION_DAYS` defaults to `0` (keep
forever); negative values are rejected. A positive value enables an hourly
reaper that deletes rows whose `at` is older than the configured window from
`audit_log` and matching `audit.forward` outbox copies, whether published or
not, in batches of at most 1,000. Unpublished copies that could not be delivered
before the cutoff are dropped. This is destructive and irreversible; the
deployment role needs `DELETE` on `audit_log` and `outbox` only when retention
is enabled. Back up and export retained records according to the organization's
recovery and compliance requirements.

`TEAMUSERS_LOGIN_ACTIVITY_RETENTION_DAYS` defaults to `90`; negative values are
rejected and `0` disables deletion. A positive value enables an hourly reaper
that deletes older `login_activity` rows in batches of at most 1,000. The
deployment role needs `DELETE` on `login_activity` only when retention is
enabled.

### Audit export

`GET /audit/export` streams the full matching audit history as JSON Lines by
default (`?format=jsonl`) or CSV (`?format=csv`). It accepts the same optional
`team_id` filter as `GET /audit`; it deliberately ignores cursor pagination so
the export includes every matching retained row. JSONL has one audit-row object
per line, while CSV has a header and one row per audit record. The response is
an attachment with a UTC-dated `audit-YYYY-MM-DD.jsonl` or `.csv` filename.
This admin-plane endpoint requires `iam:audit:any`.

Exports have a 10-minute request deadline. When it expires, the response still
returns HTTP 200 and ends at a row boundary without an error signal; a successful
status therefore does not prove completeness. Clients must compare the exported
row count with the complete matching set from filtered, paginated `GET /audit`,
or narrow the filters (for example, one `team_id` at a time) and re-run.

```sh
curl --fail-with-body -sS -OJ "$IAM_BASE_URL/audit/export" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN"

curl --fail-with-body -sS -G -OJ "$IAM_BASE_URL/audit/export" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  --data-urlencode 'format=csv' \
  --data-urlencode "team_id=$TEAM_ID"
```

### External audit forwarding

Set `TEAMUSERS_AUDIT_FORWARD_ENDPOINTS` to a comma-separated list of trusted
HTTP endpoints and `TEAMUSERS_AUDIT_FORWARD_SECRET` to a unique random secret
shared with the receiver. Use HTTPS in production and keep the secret in the
deployment secret facility; `status` and `doctor` redact both the endpoint list
and secret. Empty endpoints disable forwarding and avoid creating forwarding
outbox rows.
Audit entries written while forwarding is disabled are not queued and will not
be forwarded if forwarding is enabled later.

The service queues each audit row in the existing transactional outbox and
delivers its JSON row body asynchronously as `POST` with
`Content-Type: application/json`. The `X-Teamusers-Signature-256` header is
`sha256=<hex HMAC-SHA256>` over the exact request body. A receiver should
constant-time verify the signature and use the audit row `id` for
deduplication. Delivery is at-least-once: every configured endpoint must return
2xx before the outbox row is acknowledged, so an endpoint that already
accepted a row may receive it again when another endpoint fails. The dispatcher
retries four attempts with 1s, 4s, and 15s backoff; failed rows remain pending
for a later poll. HTTP delivery runs after the audited transaction commits, so
endpoint failures do not block or roll back that mutation. These destinations
receive audit diffs and must be treated as sensitive data processors.

The relay and notification/audit-forward dispatchers mark rows with
`published_at` after successful publication or delivery, but this service does
not delete old published rows. Define and document an operator-owned
retention/archive job only after all event consumers and notification/audit
forward endpoints have their required replay window. Never purge unpublished
rows merely because they are old; investigate delivery or broker failures
first.

The hourly session reaper deletes rows whose ordinary refresh TTL has elapsed;
it does not scan for idle timeouts, which are enforced at refresh. Successful
and failed reaper counts are visible in structured logs.

## Monitoring and incident signals

- Poll `GET /healthz`: `200 {"status":"ok"}` means the HTTP process is
  serving. It intentionally does not prove database readiness.
- Poll `GET /readyz`: `200 {"status":"ready"}` means the database `SELECT 1`
  check succeeds; `503 {"status":"not_ready"}` means it does not. Alert on a
  sustained not-ready state and on restart loops.
- Run `teamusers doctor` during deployment and incident triage. Its JSON
  report separates database, migration, and key-directory checks.
- Monitor `reaped expired sessions` and `reaped expired audit entries` counts; alert on
  `reap expired sessions failed`, `reap expired audit entries failed`,
  `record login activity failed`, `create login activity savepoint failed`,
  `audit forward delivery failed`, `audit forwarder poll failed`,
  `notification service delivery failed`, `notification notifier poll failed`,
  `outbox relay poll failed`, and repeated `publish outbox event failed` log
  records. Track pending/unpublished outbox rows and notification/audit-forward
  retry volume.
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

## SCIM provisioning

SCIM 2.0 provisioning is available under `$IAM_BASE_URL/scim/v2` when
`TEAMUSERS_SCIM_BEARER_TOKEN` is a static bearer credential. Store it in the
deployment secret facility. To revoke access, replace the configured value and
restart or roll out every replica; never put it in source control or request
logs. An empty value disables SCIM, so requests to the mounted router return
`401 application/problem+json`. Configure SCIM independently of inbound OIDC.

The bearer token can create, update, list, read, and deactivate users. It is a
service-wide credential, so restrict it to the identity provider that owns
provisioning and protect access to it as an administrator credential. Only
users with a non-empty `externalId` are in the SCIM-managed population; `POST`
requires one. List results and `totalResults` exclude erased users, service
accounts, and users with effective IAM permissions. Single-resource GET reports
unmanaged or protected users as `404`; mutations refuse protected targets.
User mutations are transactional with audit rows (`actor_id = scim`) and
lifecycle outbox events (`user.created` and `user.updated`). Disabling a user
also invalidates the user's permission version and revokes active refresh
sessions.

Create users with the SCIM media type and an idempotency key:

```sh
export SCIM_TOKEN='use-a-secret-manager-value'
export SCIM_BASE_URL="$IAM_BASE_URL/scim/v2"

curl --fail-with-body -sS -X POST "$SCIM_BASE_URL/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  -H 'Content-Type: application/scim+json' \
  -H "Idempotency-Key: $CHANGE_ID" \
  --data '{"schemas":["urn:ietf:params:scim:schemas:core:2.0:User"],"userName":"alice","externalId":"directory-123","name":{"givenName":"Alice","familyName":"Example"},"emails":[{"value":"alice@example.test","primary":true}],"active":true}'
```

`userName` and a non-empty `externalId` are required; `userName` is unique
without regard to case and `externalId` is unique. A supplied email must be a
valid address and unique across all users. Duplicate `userName`, `externalId`,
or email returns `409 uniqueness`. `externalId` is stored as a client-owned
identifier; the service-issued SCIM `id` is separate. The primary email maps to
the service's email field. If `active` is omitted it defaults to true; `active:
false` creates a disabled user.

`GET /Users` uses SCIM's one-based `startIndex` and `count` pagination, and only
returns eligible users in the externally identified population. `count`
defaults to 100, may be zero, and is capped at 1000. `totalResults` counts only
eligible users after protected accounts are excluded. The only supported filter
is `userName eq "value"`; other attributes and operators return
`400 invalidFilter`. For example:

```sh
curl --fail-with-body -sS -G "$SCIM_BASE_URL/Users" \
  -H "Authorization: Bearer $SCIM_TOKEN" \
  --data-urlencode 'filter=userName eq "alice"' \
  --data-urlencode 'startIndex=1' \
  --data-urlencode 'count=100'
```

PATCH accepts RFC 7644 `add`, `remove`, and `replace` operations for `active`,
`name`/`name.formatted`, `displayName`, and email values. Entra's filtered path
`emails[type eq "work"].value` is supported for add/replace/remove; remove does
not require a value. Changed emails must be valid addresses unique across all
users; invalid values return `400 invalidValue` and duplicates return
`409 uniqueness`.

`PUT /Users/{id}` fully replaces writable profile fields: `userName` is
required, omitted `displayName` and `emails` are cleared, and `active` defaults
to true unless explicitly false. A supplied non-empty `externalId` replaces
the client-owned identifier; if omitted it is preserved and it cannot be
cleared. Only disabled users may transition to active; attempts to activate
pending, invited, erased, or otherwise non-disabled users return `403`.

`DELETE /Users/{id}` is intentionally a soft delete: it sets `active` to false
and returns `204`; eligible users remain available to SCIM reads with
`active:false`. PATCH, PUT, and DELETE disable paths revoke sessions and
invalidate permission versions.

`GET /ServiceProviderConfig` reports PATCH and userName equality filtering as
supported, and bulk and sort as unsupported; `PUT /Users/{id}` supports full
replacement.
`GET /ResourceTypes` lists User as the only supported resource type. Groups
are not implemented because the service's groups are team-scoped and SCIM
membership provisioning would require additional team and membership semantics.
`GET /Groups` returns `501` with a
SCIM error response. Provisioning and error responses use
`application/scim+json` except the unauthenticated `401` problem response.

## Administrative impersonation

`iam:impersonate:any` is the platform-scoped permission for the admin
`POST /impersonations` endpoint and is included in the bootstrap administrator
permission set.
Assign it only to operators approved to act as other users. The endpoint also
requires fresh authentication within the previous ten minutes. Each successful
issuance records the administrator, target, reason, TTL, token `jti`, and exact
`expires_at` in the append-only audit log. Tokens have a default TTL of 300
seconds and a maximum TTL of 900 seconds.

An impersonated token is read-only at the `/me` boundary. It may call only
`GET /me`, `GET /me/password-policy`, `GET /me/sessions`, `GET /me/activity`,
and `GET /me/export`. All other `/me` methods and routes return 403
`impersonation_forbidden`, including TOTP and passkey operations. The token has
no refresh token or session and cannot be renewed.

There is no per-token `jti` revocation list in this release. Individual
impersonation tokens expire within 15 minutes of issuance, which is the maximum
remaining validity bound if an operator stops using a token.

