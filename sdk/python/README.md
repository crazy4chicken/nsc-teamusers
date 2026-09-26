# teamusers Python SDK

This package verifies teamusers Ed25519 (`EdDSA`) access tokens against the
service JWKS endpoint. The verifier fetches
`{base_url}/.well-known/jwks.json` lazily and caches the key set for one hour.

## Install

```sh
python -m pip install teamusers-sdk
```

For a checkout, install the local package instead:

```sh
python -m pip install ./sdk/python
```

## Usage

```python
from teamusers_sdk import Verifier

verifier = Verifier("https://iam.example.com", audience="orders")
claims = verifier.verify(access_token)

print(claims.subject, claims.kind, claims.perm_ver)
```

The second positional argument is the expected audience and defaults to
`"teamusers"`. A custom synchronous `fetcher(url)` can be supplied for an
application HTTP transport or tests. `cache_ttl` is measured in seconds.

## Claims

`Verifier.verify` returns an immutable `Claims` object after checking the
Ed25519 signature, issuer, expiration, audience, and required application
claims.

| Field | Type | Meaning |
| --- | --- | --- |
| `subject` (`sub`) | `str` | Non-empty user or service subject |
| `team` | `str` | Optional team claim, or `""` when absent |
| `kind` | `Literal["user", "service"]` | Subject kind |
| `perm_ver` (`permVer`) | `int` | Non-negative permission version |
| `expiry` (`exp`) | `datetime` | Expiration in UTC; `exp` exposes Unix seconds |
| `audience` (`aud`) | `str` or `tuple[str, ...]` | Verified JWT audience |

Verification failures use typed exceptions: `JWKSFetchError` for key retrieval,
`TokenVerificationError` for signature/JOSE failures, and
`TokenClaimsError` for invalid application claims. All inherit from
`SDKError`.
