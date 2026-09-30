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
authentication, lifecycle domain events, session governance (concurrency
limits + idle timeout), user-visible login activity (`/me/activity`),
inbound OIDC federation (PKCE + state cookie + opt-in upstream-MFA trust),
SCIM 2.0 inbound provisioning (external_id-scoped population, bearer auth),
audited admin impersonation (≤15min non-refreshable tokens, `act`/`imp`
claims, credential-mutation lockout).

## P3 — deferred strategic (revisit on demand)

1. **Self-service erasure for OIDC-only users** — `DELETE /me` requires a
   `password` credential, so users who registered via OIDC (no local
   password) cannot self-erase; today only admin-disable + admin erasure
   covers them. Revisit when GDPR erasure self-service is demanded: confirm
   via current OIDC session re-auth instead of a password.
