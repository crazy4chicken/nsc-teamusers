# teamusers TypeScript SDK

This package verifies teamusers Ed25519 (`EdDSA`) access tokens against the
service JWKS endpoint. The verifier fetches
`{baseURL}/.well-known/jwks.json` lazily and caches the key set for one hour.

## Install

```sh
pnpm add teamusers-sdk
```

For a checkout, install the local package instead:

```sh
pnpm add ./sdk/ts
```

## Usage

```ts
import { Verifier } from "teamusers-sdk";

const verifier = new Verifier("https://iam.example.com", {
  audience: "orders",
});
const claims = await verifier.verify(accessToken);

console.log(claims.subject, claims.kind, claims.permVer);
```

`audience` defaults to `"teamusers"`. The verifier accepts an injectable
`fetcher(url)` for a custom HTTP transport or tests. `cacheTtlMs` is measured
in milliseconds.

## Claims

`Verifier.verify` returns a typed `Claims` object after checking the Ed25519
signature, issuer, expiration, audience, and required application claims.

| Field | Type | Meaning |
| --- | --- | --- |
| `subject` (`sub`) | `string` | Non-empty user or service subject |
| `team` | `string` | Optional team claim, or `""` when absent |
| `kind` | `"user" \| "service"` | Subject kind |
| `permVer` (`perm_ver`) | `number` | Non-negative permission version |
| `expiry` (`exp`) | `Date` | Expiration time |
| `audience` (`aud`) | `string` or `readonly string[]` | Verified JWT audience |

Verification failures use typed exceptions: `JWKSFetchError` for key retrieval,
`TokenVerificationError` for signature/JOSE failures, and
`TokenClaimsError` for invalid application claims. All inherit from
`SDKError`.
