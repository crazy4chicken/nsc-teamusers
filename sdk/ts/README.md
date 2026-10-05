# teamusers TypeScript SDK

The package verifies teamusers Ed25519 (`EdDSA`) access tokens and provides the
same permission-cache, ABAC, middleware, and invalidation primitives as the Go
SDK. The core package depends only on `jose`; NATS support is an optional peer
used only by `SubscribePermissions`.

## Install

```sh
pnpm add teamusers-sdk
```

For a checkout, install the local package instead:

```sh
pnpm add ./sdk/ts
```

## Verification

```ts
import { Verifier } from "teamusers-sdk";

const verifier = new Verifier("https://iam.example.com", {
  audience: "orders",
});
const claims = await verifier.verify(accessToken);

console.log(claims.subject, claims.kind, claims.permVer);
```

`audience` defaults to `"teamusers"`. A token must contain exactly one
`aud` value and it must equal the configured audience. The verifier accepts an
injectable `fetcher(url)` for a custom HTTP transport or tests, and `cacheTtlMs`
is measured in milliseconds. Concurrent cache misses share one JWKS request,
including key-ID forced refreshes.

`Verifier.verify` returns a typed `Claims` object after checking the Ed25519
signature, issuer, expiration, audience, and required application claims.

| Field | Type | Meaning |
| --- | --- | --- |
| `subject` (`sub`) | `string` | Non-empty user or service subject |
| `team` | `string` | Optional team claim, or `""` when absent |
| `kind` | `"user" \| "service"` | Subject kind |
| `permVer` (`perm_ver`) | `number` | Non-negative permission version |
| `expiry` (`exp`) | `Date` | Expiration time |
| `audience` (`aud`) | `string` or `readonly string[]` | The single verified JWT audience |
| `authTime` (`auth_time`) | `number` | Authentication time in Unix seconds; `0` when absent |
| `amr` | `readonly string[]` | Authentication methods; empty when absent |

Legacy tokens without `auth_time` or `amr` remain valid and expose the defaults above.

Verification failures use typed exceptions: `JWKSFetchError` for key retrieval,
`TokenVerificationError` for signature/JOSE failures, and `TokenClaimsError`
for invalid application claims. All inherit from `SDKError`.

## Permission cache and authorization

`PermissionsClient` fetches the v2 snapshot from
`GET /authz/permissions/{userID}?version=2` with its service bearer token. It
requires `version: 2`, a matching `user_id`, a non-negative `perm_ver`, and
well-formed known fields. Missing, legacy, or unsupported versions and malformed
known fields raise `PermissionSnapshotError` and never downgrade. Unknown
additive snapshot and grant fields are ignored. Condition compile errors remain
attached to their grants and yield `condition_error` only when the grant's team
and permission match. Entries are single-flighted by user and cached until the
earlier of `ttlMs` (two minutes by default) and optional RFC3339 `valid_until`.

Grant `team_id` metadata is preserved. Scoped grants match only resources with
the same `resource.team_id`; a `:team` request without a non-empty
`resource.team_id` fails closed. Platform grants omit `team_id` and remain
independent of team scope metadata.

```ts
import { PermissionsClient } from "teamusers-sdk";

const permissions = new PermissionsClient("https://iam.example.com", {
  serviceToken: process.env.TEAMUSERS_SERVICE_TOKEN,
  ttlMs: 120_000,
});
const entry = await permissions.get(claims.subject, claims.permVer);
const decision = await permissions.allow(claims, "orders:read:team", {
  team_id: "team_1",
  attrs: { tier: "gold" },
});

permissions.invalidate(claims.subject);
permissions.invalidateAll();
```

`PermissionsClient.check` performs the authoritative `POST /authz/check`
request. `Client.allow` uses a matching local `permVer`; a mismatch returns
`permission version mismatch`, while a malformed/legacy snapshot returns
`invalid permission snapshot`. Neither case falls back to a flattened or
remote result. Existing fallback remains for non-protocol fetch/cache errors.
`Client.check` is always authoritative; uppercase aliases (`Get`,
`Invalidate`, `Clear`, `Allow`, and `Check`) remain available for callers
porting Go code.

## Permission keys and ABAC

`Parse`/`Validate` enforce the `resource:action:scope` grammar, including the
server's `iam` scope rules. `*` matches one segment. A leading `!` marks a deny
permission; `Match` preserves the deny bit, while authorization decisions give
a matching deny precedence over matching allows.

`CompileCondition` implements the documented zero-dependency condition subset:
member access on `subject`, `resource`, and `request`, comparisons, boolean
operators, `in`, and string/number/boolean/array literals. `resource.attrs`
indexing and comparisons involving `request.time` are supported. Conditions
are limited to 4 KiB and a bounded AST; unsupported syntax is a compile error.
A false condition excludes only that grant; a runtime condition error rejects
the whole applicable authorization with reason `condition_error`.

```ts
import { CompileCondition } from "teamusers-sdk";

const condition = CompileCondition(
  'subject.id == "user_1" && resource.attrs["tier"] == "gold"',
);
const allowed = condition.eval({
  subject: { id: claims.subject, kind: claims.kind },
  resource: { team_id: "team_1", attrs: { tier: "gold" } },
  request: { time: new Date() },
});
```

## Framework-neutral middleware

`Authenticate` reads a bearer token from a minimal `{ headers, method }`
request shape and returns `Claims`, or throws `UnauthorizedError` (HTTP 401).
`Require` builds a permission guard and throws `ForbiddenError` (HTTP 403) when
the decision is denied. `Client.middleware` and `Client.require` provide the
same helpers as instance methods.

```ts
import { Authenticate, Require } from "teamusers-sdk";

const claims = await Authenticate(request, verifier);
const guard = Require(client, "orders:read:team", (req) => ({
  team_id: String(req.teamId),
}));
await guard(request, claims);
```

`RequireFresh(maxAgeMs)` checks verified authentication evidence using
milliseconds for `maxAgeMs`. Missing, future, or stale `auth_time` throws
`ForbiddenError` with reason `step_up_required`; missing verified claims throws
`UnauthorizedError`:

```ts
import { RequireFresh } from "teamusers-sdk";

const recent = RequireFresh(10 * 60 * 1000);
await recent(request, claims);
```

## Permission invalidation events

`SubscribePermissions` listens to `iam.perm.changed`, `iam.user.disabled`, and
`iam.role.updated`. Event payloads may contain `user_ids` or `user_id`; affected
cache entries are invalidated before the optional handler runs. Pass a NATS URL
when the optional `nats` peer is installed, or pass a test/application source
implementing `subscribe(subject, handler)`. An empty URL is a no-op. Requesting
a non-empty URL without the optional peer raises `NATSDependencyError` at
subscription time. `PermissionSubscription.close()` is idempotent.

Local snapshots remain bounded by the configured TTL and any `valid_until`
deadline. Known invalidation events and `invalidateAll()` discard pre-event
in-flight snapshots for cache and current waiters; those calls fail closed
without retry or fallback. Missed or delayed events do not revoke a local
snapshot instantaneously; use `Client.check` when an authoritative decision is required.

### User deletion lifecycle events

`subscribeUserDeleted` listens to `iam.user.deleted`. The validated event has
`event_id`, `type`, `user_id`, and `at`; unlike other user lifecycle events,
`changed_fields` is omitted:

```ts
import { subscribeUserDeleted } from "teamusers-sdk";

const subscription = await subscribeUserDeleted("nats://127.0.0.1:4222", async (event) => {
  console.log(`deleted user ${event.user_id} in event ${event.event_id}`);
});
if (subscription !== null) await subscription.close();
```
