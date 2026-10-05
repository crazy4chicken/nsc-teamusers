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
| `auth_time` (`authTime`) | `int` | Authentication time in Unix seconds; `0` when absent |
| `amr` | `tuple[str, ...]` | Authentication methods; empty when absent |

Legacy tokens without `auth_time` or `amr` remain valid and expose the defaults above.

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

Permission entries use the v2 contract at
`GET /authz/permissions/{userID}?version=2`. The client requires version `2`,
a matching non-empty `user_id`, a non-negative `perm_ver`, and well-formed
known fields. Missing, legacy, or unsupported versions and malformed known
fields raise `PermissionSnapshotError` rather than downgrading. Unknown
additive snapshot and grant fields are ignored. Condition compile errors remain
attached to their grants and yield `condition_error` only when the grant's team
and permission match. Entries are single-flighted per user and cached until the
earlier of the configured TTL (two minutes by default) and optional RFC3339
`valid_until`.

`Grant.team_id` is preserved. Scoped grants match only a resource with the same
`team_id`; a `:team` request without a non-empty resource `team_id` fails
closed. Platform grants omit `team_id` and remain independent of team scope
metadata. `Get` raises `PermissionSnapshotError` for an invalid snapshot;
`Allow` returns `invalid permission snapshot` without falling back. A
`perm_ver` mismatch also fails closed. Existing remote fallback remains for
non-protocol fetch failures; `Check(subject, permission, resource)` always
performs the authoritative `POST /authz/check` request.

Permission keys use `resource:action:scope` grammar. Actions and scopes may
use their documented wildcards; a leading `!` is an explicit deny and wins
against a matching allow. `Parse`, `Validate`, `String`, `Match`, and
`MatchKeys` are available in Go-shaped and Pythonic spellings.

## Conditions and middleware

Conditions are compiled by `CompileCondition` without an expression-language
dependency. The supported context is `subject.id`, `subject.kind`,
`resource.owner_id`, `resource.team_id`, `resource.attrs[...]`, and
`request.time`, with boolean operators, comparisons, `in`, and scalar
literals. Sources are limited to 4 KiB; unsupported syntax is a compile error.
A false condition excludes only its grant, while any applicable evaluation
error rejects the authorization with reason `condition_error`.

```python
from teamusers_sdk import Client, Require

client = Client(verifier, permissions)
check = Require(client, request, claims, "orders:read:team", {"team_id": "team-1"})
```

`Authenticate(request, verifier)` returns `Claims` or raises
`UnauthorizedError` (HTTP 401). `Require` returns `Claims` or raises
`ForbiddenError` (HTTP 403). Both accept the minimal request shape
`{"headers": ..., "method": ...}`.

`RequireFresh(max_age_seconds)` returns a guard measured in seconds. It accepts
the request and already verified claims, returning the claims when `auth_time`
is fresh; missing, future, or stale timestamps raise `ForbiddenError` with
`step_up_required`. Missing claims raise `UnauthorizedError`:

```python
from teamusers_sdk import RequireFresh

fresh = RequireFresh(600)
claims = fresh(request, claims)
```

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

Local snapshot revocation is bounded by the configured TTL and any
`valid_until` deadline. Known invalidation events and `invalidate_all()` discard
pre-event in-flight snapshots for cache and current waiters; those calls fail
closed without retry or fallback. Missed or delayed events are not an
instantaneous revocation guarantee; use `Check` when an authoritative decision is required.

### User deletion lifecycle events

`SubscribeUserDeleted` listens to `iam.user.deleted`. The validated event has
`event_id`, `type`, `user_id`, and `at`; `changed_fields` is omitted:

```python
from teamusers_sdk import SubscribeUserDeleted

subscription = SubscribeUserDeleted(
    "nats://127.0.0.1:4222",
    lambda event: print(event["user_id"], event["event_id"]),
)
if subscription is not None:
    subscription.close()
```
