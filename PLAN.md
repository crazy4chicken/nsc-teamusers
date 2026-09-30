# PLAN — teamusers backlog

This file tracks **unfinished work only**. Current architecture, invariants,
and change rules live in `AGENTS.md`; shipped behavior is documented in
`docs/`. When an item here ships, delete it (and document the behavior in
`docs/` if user-visible). Do not add design prose for completed features.

Completed and therefore removed from planning: deny permissions, TOTP 2FA,
passkeys, registration/invitation flows, password policies, TS/Python SDKs,
configurable token/session TTLs, runtime signing-key rotation, audit
retention/export/forwarding, MFA enforcement policy (incl. `amr`/
`auth_time` claims), password history + breach screening, step-up
authentication.

## P2 — ecosystem & operations

1. **Lifecycle domain events on JetStream.**
   Only `perm.changed`, `user.disabled`, `role.updated`, `key.rotated` are
   published (`internal/events/relay.go`). Add `user.created`/`user.updated`/
   `team.*` etc. so peer services stop polling the admin API for provisioning.
2. **Session governance.**
   Only expiry reaping exists (`internal/store/session_reaper.go`). Add
   per-user concurrent-session limits, idle timeout, and per-team session
   policy.
3. **User-visible security activity.**
   `/me/sessions` shows live sessions but there is no login-attempt history
   or `/me/audit`. Users cannot self-verify "was that failed login me?".

## P3 — deferred strategic (explicit non-goals, revisit on demand)

4. **Inbound federation** (OIDC/SAML/LDAP login) — original non-goal;
   revisit when an org-level IdP adoption demands SSO login.
5. **SCIM inbound provisioning** — CSV import is the only bulk path today.
6. **Audited admin impersonation** — either implement with strong audit +
    time bounds for support debugging, or record an explicit rejection in
    `docs/`.
