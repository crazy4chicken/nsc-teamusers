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
