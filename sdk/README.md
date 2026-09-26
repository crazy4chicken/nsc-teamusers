# Teamusers SDKs

The repository ships verifier SDKs for applications that consume teamusers
Ed25519 (`EdDSA`) access tokens. Both SDKs fetch and cache
`/.well-known/jwks.json`, require issuer `teamusers`, validate expiration and
the expected audience, and expose the subject kind and permission version.

- [TypeScript SDK](ts/README.md): `pnpm add teamusers-sdk`
- [Python SDK](python/README.md): `python -m pip install teamusers-sdk`
- [Go SDK](go/): import the `teamusers/sdk/go` package from this repository

Each language guide includes a usage example, claims reference, cache options,
and typed verification errors. The TypeScript and Python test suites use local
Ed25519 fixtures and do not contact a network.

## Python

The Python SDK provides synchronous Ed25519 verification with a single-flight
JWKS cache, strict exactly-one audience validation, a two-minute permission
cache, local wildcard/deny matching, and zero-dependency ABAC conditions.
Install the optional `nats-py` extra to subscribe to permission invalidation
events; the core verifier does not import NATS.

## TypeScript

The TypeScript SDK provides strict exactly-one audience validation, single-flight JWKS and permission caches, local wildcard/deny matching, zero-dependency ABAC conditions, framework-neutral middleware, and optional NATS invalidation events. See [the TypeScript guide](ts/README.md) for the complete API.
