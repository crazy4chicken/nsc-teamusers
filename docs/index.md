---
layout: home

hero:
  name: teamusers
  text: Standalone IAM microservice
  tagline: Identity, authentication, and authorization for the service fleet.
  actions:
    - theme: brand
      text: Get Started
      link: /guide/getting-started
    - theme: alt
      text: API Reference
      link: /api/overview

features:
  - title: OIDC-style EdDSA JWT authentication
    details: Issue short-lived access tokens with refresh rotation, JWKS discovery, and permission-version checks.
  - title: RBAC plus ABAC authorization
    details: Resolve role and group bindings with conditional resource, action, and scope permissions.
  - title: Team-scoped delegated administration
    details: Delegate team operations while keeping platform-only resources and escalation boundaries explicit.
  - title: Complete account lifecycle
    details: Cover registration, verification, invitation, approval, password recovery, and profile erasure workflows.
  - title: TOTP and passkey MFA
    details: Protect users with RFC 6238 TOTP, one-time backup codes, and WebAuthn passkey ceremonies.
  - title: Nekostick child-process deployment
    details: Run a static Linux binary under supervised listener leases, health checks, graceful drain, and key sharing.
---
