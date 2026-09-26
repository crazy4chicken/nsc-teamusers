---
title: Authentication security
outline: 2
---

# Authentication security

## Token and refresh lifecycle

Access tokens are self-contained JWTs and are not revoked individually. Each
token carries the configured `aud` claim (default `teamusers`) and remains
usable until its ten-minute TTL expires, even when its refresh-token family is
logged out or rotated. Administrative permission changes increment
`users.perm_ver`; middleware rejects access tokens whose `perm_ver` no longer
matches the current user row.

Audience enforcement rejects tokens issued before the audience claim was
deployed, but the ten-minute TTL means old tokens expire quickly after deploy;
no token migration is needed.

Refresh tokens are opaque, stored only as SHA-256 digests, and rotate
atomically. Presenting a rotated token triggers refresh-token reuse detection
and revokes the complete family. Every family has a 90-day absolute cap
(`family_not_after`); rotation is rejected after that cap, so a user must log
in again. Ordinary refresh rows also expire after their 30-day TTL and are
removed by the hourly reaper.

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

The eight administrative keys are provisioned explicitly by
`teamusers bootstrap-admin --username <name>`. This command creates or
reconciles the platform-scoped `iam-admin` role and its binding; there is no
runtime or first-request elevation path. Keep the bootstrap database
connection and the initial user's credential under the same out-of-band
controls as other production secrets.

An admin can remove their own last `iam:*:any` grant; rerun `teamusers bootstrap-admin --username <name>` to restore the role and binding.

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

Confirmation validates the configured password policy, replaces or creates the
password credential, revokes every refresh session, and clears lockout state in
one transaction. The reset-request audit action is written only when a token
and notification were committed, so audit records do not turn the public
request endpoint into an account-existence oracle. Reset completion is audited
against the recovered user.

Administrator-provisioned password credentials carry a `must_change` flag. A
successful password login for such an account returns `403 password_change_required`
and a ten-minute EdDSA `password_change` token instead of issuing an access or
refresh token. The token is accepted only by
`POST /me/password`, which still verifies the current password; all other
endpoints reject it. Registration, invitation acceptance, and password-reset
completion clear the flag. A successful forced change clears the flag and
revokes every refresh session, so the user must sign in again with the new
password.

## Invitation tokens

Invitation tokens are 32-byte random values rendered as base64url text. Only
the SHA-256 digest is stored in `verification_tokens`; the plaintext is carried
only in the transactional `notify.user.invited` outbox payload. Tokens are
single-use and expire after seven days. Resending an invitation marks every
previous unused invitation token used before issuing a replacement, and
cancelling an invitation deletes the user and cascaded token rows.

The public acceptance endpoint is rate-limited per client IP and returns the
generic `invalid_token` problem for unknown, expired, used, wrong-kind,
cancelled, and already-active invitation tokens. It validates the configured
password policy before creating the password credential. An invited account
cannot log in before acceptance; password login returns `403 account_pending`.

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

Passwords must meet the configured minimum Unicode length and contain at least
one letter and one digit. The policy is enforced at registration and when an
administrator creates or rotates a password credential; weak values are
rejected rather than silently modified.


## Profile lifecycle and erasure

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
Foreign keys and append-only audit records need the stable user ULID for
referential history, so the service replaces the username and email with
generated `deleted_<ULID>` values, clears the display name, and disables the
row. All credential kinds and refresh sessions are deleted/revoked in the
same transaction. Audit records retain the opaque ULID and action metadata,
not the former profile, password, token, or credential material. This gives
operational history without retaining directly identifying profile data.

The self-service export includes profile metadata, memberships, effective
permission keys, active session metadata, TOTP-enabled state, and passkey
count. It deliberately excludes credential hashes, service secrets, TOTP
seeds, backup-code digests, and serialized passkey material.

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
