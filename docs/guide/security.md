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

Introspection deliberately has two branches. Access-token introspection
validates the JWT and the current active user but does not consult a refresh
session, so it follows the access-token contract above rather than refresh
revocation state. Refresh-token introspection checks the stored session and its
revocation/expiry state. This divergence preserves stateless access-token
validation while retaining operational refresh-token status.

## Admin-plane dogfooding

The administrative HTTP plane is intentionally dogfooded through the same
permission engine used by runtime authorization. Every request must carry an
active `kind=user` access token; service-kind tokens are rejected with `403`.
The route family is resolved against the caller's current role bindings on each
request (the plane is low QPS), and a missing `iam:*` key fails closed with
`insufficient_permissions`.

The ten enumerated administrative `iam:<area>:any` keys plus the
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

## Password policies

Password requirements are DB-backed rules stored in PostgreSQL and managed
through the administrative password-policy API. Each rule may set
`min_length` (from 1 through 1024 Unicode runes), `require_letter`,
`require_upper`, `require_lower`, `require_digit`, and `require_symbol`.
Nullable or omitted fields are unset rather than false, so they can fall
through during resolution. Password policies target the generic subject model;
see [Subject targeting](/guide/subjects) for the `(subject_kind, subject_id)`
model and its membership and role-binding traversal.

A rule is a JSON record whose requirement fields are all optional. This rule
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
  "require_symbol": true
}
```

```sh
curl --fail-with-body -sS -X POST "$IAM_BASE_URL/policies/password" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"name":"platform administrators","priority":100,"subject_kind":"role","subject_id":"01JROLE…","min_length":20,"require_upper":true,"require_lower":true,"require_digit":true,"require_symbol":true}'
```

`PATCH /policies/password/{id}` changes individual fields; sending a
requirement field as `null` unsets it so lower-priority rules and the default
apply again:

```sh
curl --fail-with-body -sS -X PATCH "$IAM_BASE_URL/policies/password/01JPOLICY…" \
  -H "Authorization: Bearer $ADMIN_ACCESS_TOKEN" \
  -H 'Content-Type: application/json' \
  --data '{"require_symbol":null,"priority":200}'
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
| User `alice` | 50 | `min_length: 24`, `require_digit: false` |
| Role `iam-admin` | 100 | `require_symbol: true` |

the resolved policy uses `min_length: 24` (the user rule outranks the team
rule), `require_symbol: true` (only the role rule sets it),
`require_digit: false` (explicitly relaxed by the user rule), and
`require_letter: true` (from the built-in default, because no rule sets it).

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
{"min_length":24,"require_letter":true,"require_upper":false,"require_lower":false,"require_digit":false,"require_symbol":true}
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

The service uses `X-Forwarded-For` when the direct TCP peer is loopback or
matches one of the CIDRs or IP addresses configured in
`TEAMUSERS_TRUSTED_PROXIES`. In either case, only the first address in the
header is used. For any other peer, the direct `RemoteAddr` is authoritative
and the forwarded header is ignored. The default trusted-proxy list is empty,
so deployments using a non-loopback proxy must configure its fixed addresses;
accepting forwarded headers from arbitrary peers would make IP rate limits and
audit metadata attacker-controlled.

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
