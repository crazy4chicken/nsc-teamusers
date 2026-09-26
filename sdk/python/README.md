# teamusers Python SDK

This package verifies teamusers Ed25519 (`EdDSA`) access tokens, caches the
service JWKS document, and provides local permission and ABAC authorization
helpers. The verifier and middleware are synchronous; no event loop is
required for ordinary SDK use.

## Install

```sh
python -m pip install teamusers-sdk
```

For a checkout, install the local package instead:

```sh
python -m pip install ./sdk/python
```

NATS permission invalidation is optional:

```sh
python -m pip install 'teamusers-sdk[nats-py]'
```

## Verification

```python
from teamusers_sdk import Verifier

verifier = Verifier("https://iam.example.com", audience="orders")
claims = verifier.verify(access_token)

print(claims.subject, claims.kind, claims.perm_ver)
```

The second positional argument is the expected audience and defaults to
`"teamusers"`. A custom synchronous `fetcher(url)` can be supplied for an
application HTTP transport or tests. `cache_ttl` is measured in seconds.
Concurrent verification calls share one JWKS fetch, including a key-ID miss
refresh.

`Verifier.verify` returns an immutable `Claims` object after checking the
Ed25519 signature, issuer, expiration, exactly-one-entry audience, and required
application claims.

| Field | Type | Meaning |
| --- | --- | --- |
| `subject` (`sub`) | `str` | Non-empty user or service subject |
| `team` | `str` | Optional team claim, or `""` when absent |
| `kind` | `Literal["user", "service"]` | Subject kind |
| `perm_ver` (`permVer`) | `int` | Non-negative permission version |
| `expiry` (`exp`) | `datetime` | Expiration in UTC; `exp` exposes Unix seconds |
| `audience` (`aud`) | `str` or `tuple[str, ...]` | Verified JWT audience; lists must contain exactly one value |

Verification failures use typed exceptions: `JWKSFetchError` for key retrieval,
`TokenVerificationError` for signature/JOSE failures, and
`TokenClaimsError` for invalid application claims. All inherit from
`SDKError`.

## Permissions

```python
from teamusers_sdk import PermissionsClient

permissions = PermissionsClient(
    "https://iam.example.com",
    service_token="service-token",
)
entry = permissions.Get("user-id", claims.perm_ver)
allowed, reason = permissions.Allow(claims, "orders:read:team", {"team_id": "team-1"})
```

Permission entries are fetched from
`GET /authz/permissions/{userID}`, cached for two minutes by default, and
single-flighted per user. A token `perm_ver` mismatch bypasses the cached
entry. Use `Invalidate(user_id)`, `InvalidateAll()`, or `Clear()` after an
application-side change. `Check(subject, permission, resource)` performs the
authoritative `POST /authz/check` request.

Permission keys use `resource:action:scope` grammar. Actions and scopes may
use their documented wildcards; a leading `!` is an explicit deny and wins
against a matching allow. `Parse`, `Validate`, `String`, `Match`, and
`MatchKeys` are available in Go-shaped and Pythonic spellings.

## Conditions and middleware

Conditions are compiled by `CompileCondition` without an expression-language
dependency. The supported context is `subject.id`, `subject.kind`,
`resource.owner_id`, `resource.team_id`, `resource.attrs[...]`, and
`request.time`, with boolean operators, comparisons, `in`, and scalar
literals. Sources are limited to 4 KiB and unsupported or failed evaluations
deny access.

```python
from teamusers_sdk import Client, Require

client = Client(verifier, permissions)
check = Require(client, request, claims, "orders:read:team", {"team_id": "team-1"})
```

`Authenticate(request, verifier)` returns `Claims` or raises
`UnauthorizedError` (HTTP 401). `Require` returns `Claims` or raises
`ForbiddenError` (HTTP 403). Both accept the minimal request shape
`{"headers": ..., "method": ...}`.

## Event invalidation

```python
subscription = permissions.SubscribePermissions(
    "nats://127.0.0.1:4222",
    lambda user_ids: print(user_ids),
)
# later
subscription.Close()
```

The optional subscription listens to `iam.perm.changed`,
`iam.user.disabled`, and `iam.role.updated`, invalidating each event's
`user_ids`. Tests and applications that already own a connection can inject a
subscription source object with `subscribe(subject, callback)` instead of a
URL. The missing optional dependency is reported as `NATSUnavailableError`
when `SubscribePermissions` is called; importing the core SDK never requires
NATS.
