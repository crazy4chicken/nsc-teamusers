---
title: Authentication security
outline: 2
---

# Authentication security

## Token and refresh lifecycle

Access tokens are self-contained JWTs and are not revoked individually. Each
token carries the configured `aud` claim (default `teamusers`) and remains
usable until the configured access-token TTL (`TEAMUSERS_ACCESS_TOKEN_TTL`,
10 minutes by default) expires, even when its refresh-token family is logged
out or rotated. Administrative permission changes increment `users.perm_ver`;
middleware rejects access tokens whose `perm_ver` no longer matches the
current user row.

Audience enforcement rejects tokens issued before the audience claim was
deployed, while tokens otherwise expire according to the access-token TTL
applied at issuance (10 minutes by default); no token migration is needed.

Refresh tokens are opaque, stored only as SHA-256 digests, and rotate
atomically. Presenting a rotated token triggers refresh-token reuse detection
and revokes the complete family. Every family has an absolute cap configured
by `TEAMUSERS_SESSION_FAMILY_TTL` (90 days by default; `family_not_after`), which
must be at least the configured refresh-token TTL
(`TEAMUSERS_REFRESH_TOKEN_TTL`, 30 days by default). Rotation is rejected
after that cap, so a user must log in again. Ordinary refresh rows also expire
after the configured refresh-token TTL and are removed by the hourly reaper.

Session policies are stored in `session_policies` and target the platform
default (`subject_kind = 'default'`, empty `subject_id`), a team, a group, or a
role. Each non-null field resolves independently from the highest-priority
matching policy; an unset `max_concurrent_sessions` or `idle_timeout_minutes`
does not impose a limit. When a new user session would exceed its concurrent-
session limit, the service revokes the least recently rotated active session(s)
with `revoke_reason = 'evicted_by_policy'` and admits the new session. Rotation
creates a replacement row with a new creation time, which determines this
ordering. Service-account sessions are exempt from user session policies.
`last_active_at` is initialized at session creation and updated only after a
successful refresh. Idle expiry is checked on refresh, not on ordinary API
requests: an idle session's refresh is rejected and the row is revoked with
`revoke_reason = 'session_idle_expired'`. The hourly reaper remains limited to
ordinary refresh-token expiry.

Introspection deliberately has two branches. Access-token introspection
validates the JWT and the current active user but does not consult a refresh
session, so it follows the access-token contract above rather than refresh
revocation state. Refresh-token introspection checks the stored session and its
revocation/expiry state. This divergence preserves stateless access-token
validation while retaining operational refresh-token status.

The service records resolved password, passkey, OIDC, and MFA authentication
outcomes in `login_activity`, including timestamp, client IP, user agent,
method, and result; passwords and tokens are never stored. Writes are
best-effort and logged without blocking authentication. `GET /me/activity`
returns cursor pages ordered by descending activity ID and filters strictly to
the caller's `user_id`. When a failed attempt cannot be tied to a user, its
attempted username is stored with a null `user_id` and is not exposed through
the self-service endpoint.

## Inbound OpenID Connect federation

Inbound federation is disabled when `TEAMUSERS_OIDC_ISSUER` is empty. Configure the issuer, client ID, client secret, and callback URL together; use HTTPS issuer and callback URLs in production. The authorization-code exchange has a ten-second timeout. The begin endpoint creates random state, nonce, and PKCE verifier values, stores the state and nonce digests plus the PKCE S256 challenge and verifier server-side for five minutes, and keeps state single-use.

The begin endpoint sets a `__Host-oidc_state` cookie containing the state digest with `HttpOnly`, `SameSite=Lax`, `Secure`, `Path=/`, and no `Domain`. `Secure` is unconditional because production TLS terminates at the trusted reverse proxy; the browser callback must use the public HTTPS origin. At callback, the service constant-time checks the cookie against the state query, consumes the state, and sends the stored verifier to the token endpoint. Missing or mismatched cookies and replayed states are rejected.

The callback verifies the ID-token signature against cached issuer JWKS while enforcing the header-algorithm allowlist. It checks `iss`, `aud`, `exp`, the nonce, requires `iat` to be no more than ten minutes old and no more than 30 seconds in the future, and rejects `nbf` values more than 30 seconds in the future. An unknown `kid` triggers a JWKS refresh. Unverified email claims are never used to associate an account: an existing `(issuer, sub)` identity can sign in directly, while linking by email and just-in-time user creation require `email_verified: true`. An email match can link only when the local `email_verified_at` is set and the local status is neither `pending` nor `invited`; erased users are not linkable. Refused links return `403 oidc_link_refused` without changing local credentials. Closed registration rejects unknown users; approval mode creates a pending user; open mode creates an active user. Newly provisioned OIDC users emit the `user.created` lifecycle event.

The callback returns JSON, not a frontend redirect, and never persists the provider's ID token. OIDC primary authentication sets `auth_time` to the callback time and contributes `amr: ["ext"]`; a local TOTP step-up retains that evidence and adds `otp` to the final token pair. The callback can return a JSON TOTP or enrollment challenge. Upstream `amr`/`acr` claims satisfy MFA only when `TEAMUSERS_OIDC_TRUST_UPSTREAM_MFA=true` (default `false`); otherwise local MFA remains required when policy demands it. When trust is enabled, configured `TEAMUSERS_OIDC_MFA_ACR_VALUES` are exact `acr` matches; the service does not split or infer values from delimiters. Login activity records the `oidc` method for both successful and failed callbacks and uses the existing per-IP limiter.

## Admin-plane dogfooding

The administrative HTTP plane is intentionally dogfooded through the same
permission engine used by runtime authorization. Every request must carry an
active `kind=user` access token; service-kind tokens are rejected with `403`.
The route family is resolved against the caller's current role bindings on each
request (the plane is low QPS), and a missing `iam:*` key fails closed with
`insufficient_permissions`.

The enumerated administrative `iam:<area>:any` keys plus the
`iam:*:any` wildcard are provisioned explicitly by
`teamusers bootstrap-admin --username <name>`. This command creates or
reconciles the platform-scoped `iam-admin` role and its binding; there is no
runtime or first-request elevation path. `iam:*:any` is a platform wildcard
covering current and future IAM areas at the `:any` scope. On every service
startup, permission reconciliation intentionally restores the complete bootstrap
permission set—including `iam:*:any`—on an existing platform `iam-admin` role.
Deliberate removals from that role are therefore not sticky.
Keep the bootstrap database connection and the initial user's credential under
the same out-of-band controls as other production secrets.

An admin can remove their own last `iam:*:any` grant; rerun
`teamusers bootstrap-admin --username <name>` to restore the role and binding.

## Fresh authentication for administrative mutations

Sensitive administrative operations require a user access token whose
`auth_time` is no more than ten minutes old. A stale timestamp returns
`403 step_up_required`. This guard applies to:

- `DELETE /users/{id}`, `POST /users/{id}/disable`,
  `POST /users/{id}/approve`, `POST /users/{id}/credentials`,
  `DELETE /users/{id}/totp`, `DELETE /users/{id}/sessions`, and
  `DELETE /users/{id}/sessions/{sid}`.
- `PUT /roles/{id}/permissions`, `POST /bindings`,
  `DELETE /bindings/{id}`, `POST /policies/mfa`,
  `PATCH /policies/mfa/{id}`, `DELETE /policies/mfa/{id}`, and
  `POST /keys/rotate`.
- `PATCH /users/{id}` when the patch includes a non-null `email` value or
  sets `status` to `disabled`; username, display-name, and active-status-only
  patches do not require fresh authentication.
- `POST /users/batch` when `op` is `disable`; `enable` does not require
  fresh authentication.
- `PUT /groups/{id}/members` and `POST /groups/{id}/members/batch`, which can
  grant group-derived privileges.
- `POST /policies/password`, `PATCH /policies/password/{id}`, and
  `DELETE /policies/password/{id}`, because these operations can weaken
  password requirements.

`POST /users`, `POST /users/import`, and `DELETE /roles/{id}` remain guarded by
their normal administrative permissions but do not require fresh
authentication. Other admin operations continue to use their existing
permission checks.

## Administrative impersonation

`POST /impersonations` is a high-risk support operation guarded by
`iam:impersonate:any` and the same ten-minute fresh-authentication step-up as
other sensitive administrative mutations. Each request requires a reason of at
least three characters. Successful issuance records an append-only
`impersonation.started` audit row containing the administrator, target, reason,
TTL, token `jti`, and exact `expires_at`.

The access token represents the target user (`kind=user`) and carries
`act: {"sub": "<administrator-id>"}` and `imp: true`. It sets `auth_time` to
zero, so it never satisfies step-up. The TTL defaults to five minutes and is
capped at fifteen minutes. No refresh token or session row is created; the
token cannot be renewed.
Trusted service introspection also returns the `act` and `imp` values for an
active impersonation access token.

The `/me` router permits impersonated tokens to use only `GET /me`,
`GET /me/password-policy`, `GET /me/sessions`, `GET /me/activity`, and
`GET /me/export`. Every other `/me` method or route is rejected with 403
`impersonation_forbidden`, including profile changes, account erasure, session
revocation, TOTP, and passkey operations.

Audit events emitted under an impersonated subject retain the target user as
`actor_id` and record the administrator from `act.sub` as
`after.impersonated_by`. There is no per-`jti` revocation list; an individual
impersonation token cannot be revoked early by its identifier. Its 15-minute
maximum expiry is therefore the upper bound on its remaining validity.

Only active non-service accounts may be targets. Self-impersonation and
impersonation of any account with effective `iam:*` permissions are denied so
the token cannot grant administrative access.

## Password policies

Password requirements are DB-backed rules stored in PostgreSQL and managed
through the administrative password-policy API. Each rule may set
`min_length` (from 1 through 1024 Unicode runes), `require_letter`,
`require_upper`, `require_lower`, `require_digit`, `require_symbol`,
`history_count` (0 through 24), and `breach_check`. Nullable or omitted fields
are unset rather than false, so they fall through during resolution. Password
policies target the generic subject model; see [Subject targeting](/guide/subjects)
for the `(subject_kind, subject_id)` model and its membership and role-binding
traversal.

`history_count` defaults to 0 and prevents reuse of the most recently set
passwords. The service stores only Argon2id hashes in `password_history`, keeps
the maximum count configured by matching policies (capped at 24), and prunes
older entries as passwords are set. `breach_check` defaults to false. When a
matching rule enables it and `TEAMUSERS_PWNED_PASSWORDS_ENABLED=true` (or
`--pwned-passwords-enabled`) is set, the service checks the password against
the HIBP range API using only the first five hexadecimal characters of its
SHA-1 digest; the plaintext and full digest are never sent. Requests time out
after five seconds. HIBP errors fail open and emit a WARN log, so screening is
availability-biased and external calls remain opt-in.

A rule is a JSON record whose policy fields are all optional. This rule
targets the holders of one role and asks for twenty runes with every
character class:

```json
{
  "name": "platform administrators",
  "priority": 100,
  "subject_kind": "role",
  "subject_id": "01JROLE…",
  "min_length": 20,
  "require_upper": true,
  "require_lower": true,
  "require_digit": true,
  "require_symbol": true,
  "history_count": 5,
  "breach_check": true
}
```

```sh
curl --fail-with-body -sS -X POST "$IAM_BASE_URL/policies/password" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"platform administrators","priority":100,"subject_kind":"role","subject_id":"01JROLE…","min_length":20,"require_upper":true,"require_lower":true,"require_digit":true,"require_symbol":true,"history_count":5,"breach_check":true}'
```

`PATCH /policies/password/{id}` changes individual fields; sending a policy
field as `null` unsets it so lower-priority rules and the default apply again:

```sh
curl --fail-with-body -sS -X PATCH "$IAM_BASE_URL/policies/password/01JPOLICY…" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"require_symbol":null,"history_count":null,"breach_check":null,"priority":200}'
```

When multiple rules match a user, rules are merged independently per field.
The highest-priority rule that sets a field supplies that field; fields that no
matching rule sets use the built-in default. The built-in default requires at
least 12 Unicode runes, one letter, and one digit. It does not require an
uppercase letter, lowercase letter, or symbol unless a matching rule sets that
requirement.

For example, when these three rules all match one user:

| Rule target | Priority | Fields set |
| --- | --- | --- |
| Team `engineering` | 10 | `min_length: 16` |
| User `alice` | 50 | `min_length: 24`, `require_digit: false`, `history_count: 5` |
| Role `iam-admin` | 100 | `require_symbol: true`, `breach_check: true` |

the resolved policy uses `min_length: 24` (the user rule outranks the team
rule), `require_symbol: true` (only the role rule sets it),
`require_digit: false` (explicitly relaxed by the user rule),
`history_count: 5`, `breach_check: true`, and `require_letter: true` (from the
built-in default, because no rule sets it).

Adding or tightening a policy does not revalidate or invalidate an existing
password. The new requirements are enforced the next time that user sets or
changes a password.

Password validation resolves the effective policy for the target user in
invitation acceptance, password-reset completion, self-service password
changes, administrator password-credential creation or rotation for an
existing user, and the temporary password generated for an auto-created
startup administrator. Public registration, CSV import, and administrative
user creation (`password` or `initial_password`) use the built-in default
instead. This is a documented limitation because those paths validate before
the new user has memberships or role bindings.

Frontends can pre-validate against the effective policy with authenticated
query endpoints:

- `GET /me/password-policy` accepts a user bearer or a `password_change` token
  for users who must change their password, returning that user's resolved
  policy for pre-validation before `POST /me/password`.
- `GET /users/{id}/password-policy` requires `iam:users:any` and returns the
  resolved policy for the administrative target user.

```sh
curl -fsS "$IAM_BASE_URL/me/password-policy" \
  -H "Authorization: Bearer $ACCESS_TOKEN"
```

```json
{"min_length":24,"require_letter":true,"require_upper":false,"require_lower":false,"require_digit":false,"require_symbol":true,"history_count":5,"breach_check":false}
```

Both endpoints return only the merged policy fields, not the raw rules. The
`iam:policies:any` permission is security-critical: policy administrators can
create or change rules that weaken any account's password requirements. This is
an accepted administrative risk; grant the permission only to trusted
administrators.

Invitation acceptance and password-reset confirmation validate passwords
server-side but do not expose a policy-query endpoint for those token-based
flows.

## TOTP and recovery credentials

TOTP uses RFC 6238 with SHA-1, six-digit codes, a 30-second step, and a
one-step clock-skew window. The enrollment secret must be retained in plaintext
in the `credentials.hash` column because the server must recompute future TOTP
codes; unlike a password, it cannot be verified from a one-way hash. This is a
deliberate at-rest tradeoff: protect database backups and deployment database
credentials as sensitive MFA seed material, restrict credential-table access,
and rotate/delete the seed when the user disables TOTP.
The enrollment secret is returned only during pending enrollment. Backup codes
are returned only once at confirmation. Each displayed
`xxxx-xxxx-xxxx-xxxx` code has 16 lowercase alphanumeric characters; the
canonical no-dash lowercase value is hashed with SHA-256, and all ten digests
are stored in one `backup_codes` credential row as a JSON array. This gives
about 81 bits of entropy per code without adding Argon2 work to every MFA
attempt.

## Password and lost-MFA recovery threat model

Password-reset requests are intentionally non-identifying: the request endpoint
returns an empty `204` for known, unknown, inactive, malformed, and otherwise
unsuccessful requests. A matching active account causes a 32-byte random token
to be stored only as a SHA-256 digest with a one-hour expiry and single-use
consumption. The plaintext is carried only in the transactional notification
outbox payload. The endpoint uses both client-IP and normalized-login buckets;
confirmation uses a separate per-IP bucket to bound token guessing.

Confirmation validates the recovered user's effective password policy, replaces
or creates the password credential, revokes every refresh session, and clears
the `must_change` flag in one transaction. The reset-request audit action is
written only when a token
and notification were committed, so audit records do not turn the public
request endpoint into an account-existence oracle. Reset completion is audited
against the recovered user.

Administrator-provisioned password credentials carry a `must_change` flag. A
successful password login for such an account returns `403 password_change_required`
and an EdDSA `password_change` token using the configured access-token TTL
(10 minutes by default) instead of issuing an access or refresh token. The
token is accepted by `POST /me/password`, which still verifies the current
password, and by `GET /me/password-policy`, which lets users required
to change their password pre-validate the effective policy. All other endpoints
reject it. Registration, invitation acceptance, and password-reset completion
clear the flag. A successful forced change clears the flag and revokes every
refresh session, so the user must sign in again with the new password.

## Invitation tokens

Invitation tokens are 32-byte random values rendered as base64url text. Only
the SHA-256 digest is stored in `verification_tokens`; the plaintext is carried
only in the transactional `notify.user.invited` outbox payload. Tokens are
single-use and expire after seven days. Resending an invitation marks every
previous unused invitation token used before issuing a replacement, and
cancelling an invitation deletes the user and cascaded token rows.

The public acceptance endpoint is rate-limited per client IP and returns the
generic `invalid_token` problem for unknown, expired, used, wrong-kind,
cancelled, and already-active invitation tokens. It validates the invited
user's effective password policy before creating the password credential.
An invited account cannot log in before acceptance; password login returns
`403 account_pending`.

Backup-code regeneration requires an authenticated user bearer, an active TOTP
credential, and the current password. Ten new random codes replace the prior
single JSON digest row atomically; old codes therefore fail immediately and
plaintext codes are returned only once. If a user loses both their authenticator
and backup codes, an administrator with `iam:users:any` may delete that user's
active/pending TOTP and backup credentials through `DELETE /users/{id}/totp`.
That operation is transactional, audited as `admin.totp_reset`, and deliberately
does not reveal credential material.

Password and MFA failures increment the per-user lockout counter. At the
configured threshold, the account is locked until the configured deadline;
successful login resets the counter and deadline. An attacker who can submit
enough failures can deliberately lock a victim out (a lockout DoS); the
per-IP limiter is a partial mitigation, not a complete defense against
distributed sources.

## Profile lifecycle and erasure

`PATCH /me` accepts `username` and `display_name` independently; the username is trimmed using the same rules as administrative user updates. Username changes retain the stable user ID and existing sessions, while password login must use the new username. Discoverable passkey login remains anchored to the stable user ID rather than the mutable username.

Usernames are stored lowercase: any case is accepted on write paths (registration, invitations, admin or self-service updates, CSV import) and normalized in the store layer, while login comparison stays case-insensitive via the `CITEXT` column.

Email changes require the current password before a request is accepted. The
replacement address is checked for valid syntax and ownership, but is not
written to `users` until the caller presents a single-use `email_change` token.
The token is valid for 24 hours; only its SHA-256 digest is stored in
`verification_tokens`, while the plaintext is carried transactionally in a
`notify.email.change_verification` outbox payload addressed to the new email.
Confirmation is bound to the bearer subject, sets `email_verified_at`, and
records only opaque user IDs in the audit target.

Changing an email address does not revoke any existing sessions. This is deliberate:
an email change is not treated as a credential-compromise event. A password change
or password reset, by contrast, revokes all existing sessions.

`DELETE /me` is an erasure operation rather than a physical row deletion.
Foreign keys and retained audit records use the stable user ULID for
referential history, so the service replaces the username and email with
generated `deleted_<ULID>` values, clears the display name, and disables the
row. All credential kinds and refresh sessions are deleted/revoked in the
same transaction. While retained, audit records preserve the opaque ULID and
action metadata, not the former profile, password, token, or credential
material.

The self-service export includes profile metadata, memberships, effective
permission keys, active session metadata, TOTP-enabled state, and passkey
count. It deliberately excludes credential hashes, service secrets, TOTP
seeds, backup-code digests, and serialized passkey material.

## Audit retention and forwarding

Audit rows are append-only while retained; the application does not update
them. The default `TEAMUSERS_AUDIT_RETENTION_DAYS=0` keeps rows indefinitely.
A positive retention value opts into hourly deletion of `audit_log` rows and
matching `audit.forward` outbox copies whose audit timestamp is older than that
window, including unpublished copies that could not be delivered in time. Those
rows may no longer be available to `GET /audit` or `GET /audit/export`.
When retention is enabled, the deployment role needs `DELETE` on both
`audit_log` and `outbox`.
Append-only applies only within the retention window; deployments requiring
permanent history must keep retention disabled and maintain protected backups
or immutable archives.

`GET /audit/export` requires `iam:audit:any` and exports retained audit rows.
When external forwarding is enabled, the full row, including its diff, is sent
to configured endpoints as an HMAC-SHA256-signed HTTP POST. HMAC authenticates
and protects body integrity but does not encrypt it; use HTTPS, restrict
endpoint access, and treat the signing secret and forwarded audit data as
sensitive. Delivery is at-least-once, so receivers must deduplicate by audit
row ID.

Audit entries written while forwarding is disabled are not queued and will not
be forwarded if forwarding is enabled later.

### Login activity retention

Login activity is retained separately from the append-only audit log.
`TEAMUSERS_LOGIN_ACTIVITY_RETENTION_DAYS` defaults to 90; negative values are
rejected, and `0` disables deletion. A positive value enables hourly deletion
of older `login_activity` rows in batches of at most 1,000. The deployment role
needs `DELETE` on `login_activity` when retention is enabled. Stored usernames
and user agents have control characters removed and are limited to 256 and 512
UTF-8-safe bytes, respectively. Rate-limited requests are not recorded as
authentication failures.

## Passkey and WebAuthn ceremonies

WebAuthn ceremony sessions are stored server-side for five minutes. Finishing a
ceremony atomically deletes the matching challenge only while it is unexpired;
expired, consumed, and unknown challenges are indistinguishable. This makes a
challenge single-use even when two finish requests race.

Registration requests `attestation = "none"` and accepts only the resulting
unattributed credential policy. The service does not collect or retain
attestation identity claims, so deployments that require authenticator
allow-lists need a separate policy before enabling enrollment.

Login supports both username-bound assertions and discoverable (usernameless)
assertions. A username supplied to login begin is not an identity oracle:
unknown users and users without a passkey return the same generic
authentication problem. Discoverable login resolves the account only after the
authenticator returns its credential ID and user handle; status and lockout
checks still run before token issuance.

Username-bound begin performs a lookup before issuing assertion options, so its
timing can differ from a discoverable begin. The endpoint is IP- and
username-rate-limited, and unknown users still receive the same generic
authentication problem.

## Trusted client address

The service uses `X-Forwarded-For` only when the direct TCP peer is loopback or
matches one of the CIDRs or IP addresses configured in
`TEAMUSERS_TRUSTED_PROXIES`. For a trusted peer, it walks the forwarded chain
from right to left, skips trusted proxy hops, and selects the rightmost
non-trusted address. If the direct peer is not trusted, its `RemoteAddr` is
authoritative and the forwarded header is ignored. The default trusted-proxy
list is empty, so deployments using a non-loopback proxy must configure its
fixed addresses. The trusted edge proxy must overwrite any client-supplied
`X-Forwarded-For` with the source address it observes before forwarding; do not
preserve or blindly append an untrusted client-provided chain.

## Signing keys

All replicas must share the configured key directory. The directory contains
the private Ed25519 keys, public JWKs, and an `ACTIVE` marker naming the key
used for new tokens. If no key exists, the service auto-generates one and logs
a warning; this is intentionally retained for supervision-friendly startup,
but independent key directories cause replicas to reject one another's JWTs.
Keep the directory on shared, protected storage and preserve its permissions.

## Rate limits and password work

Password login is limited by a five-per-minute bucket per IP and normalized
username, plus a coarse 30-per-minute bucket per IP. Client-credentials
requests share the coarse IP bucket. Refresh, logout, and introspection also
use the coarse per-IP bucket. Limiter state is bounded at 10,000 keys, stale
entries are swept lazily, and Argon2 verification has four concurrent slots;
when all slots remain busy for two seconds the endpoint returns `429` with
`application/problem+json`.
