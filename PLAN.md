# PLAN — teamusers backlog

This file tracks **unfinished work only**. Current architecture, invariants,
and change rules live in `AGENTS.md`; shipped behavior is documented in
`docs/`. When an item here ships, delete it (and document the behavior in
`docs/` if user-visible). Do not add design prose for completed features.

Completed and therefore removed from planning: deny permissions, TOTP 2FA,
passkeys, registration/invitation flows, password policies, TS/Python SDKs,
configurable token/session TTLs, runtime signing-key rotation, audit
retention/export/forwarding.


## P1 — policy enforcement

1. **MFA enforcement policy.**
   TOTP is voluntary; admins can only reset it. Add per-team/role "MFA
   required" policy enforced at login, plus an `amr` claim so downstream
   services and `/authz/check` conditions can reason about authentication
   strength.
2. **Password history + breached-password screening.**
   `password_policies` covers length/character classes only. Add
   no-reuse-of-last-N history and optional HIBP k-anonymity breach screening
   at set/reset time.
3. **Step-up authentication for sensitive operations.**
   No way to require fresh (recent) auth for high-impact actions. Add a
   recent-auth timestamp/`max_age` concept consumable by `/authz/check`
   conditions and admin mutations.

## P2 — ecosystem & operations

4. **Lifecycle domain events on JetStream.**
   Only `perm.changed`, `user.disabled`, `role.updated`, `key.rotated` are
   published (`internal/events/relay.go`). Add `user.created`/`user.updated`/
   `team.*` etc. so peer services stop polling the admin API for provisioning.
5. **Session governance.**
   Only expiry reaping exists (`internal/store/session_reaper.go`). Add
   per-user concurrent-session limits, idle timeout, and per-team session
   policy.
6. **User-visible security activity.**
   `/me/sessions` shows live sessions but there is no login-attempt history
   or `/me/audit`. Users cannot self-verify "was that failed login me?".

## P3 — deferred strategic (explicit non-goals, revisit on demand)

7. **Inbound federation** (OIDC/SAML/LDAP login) — original non-goal;
   revisit when an org-level IdP adoption demands SSO login.
8. **SCIM inbound provisioning** — CSV import is the only bulk path today.
9. **Audited admin impersonation** — either implement with strong audit +
    time bounds for support debugging, or record an explicit rejection in
    `docs/`.
