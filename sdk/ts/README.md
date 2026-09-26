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

Verification failures use typed exceptions: `JWKSFetchError` for key retrieval,
`TokenVerificationError` for signature/JOSE failures, and `TokenClaimsError`
for invalid application claims. All inherit from `SDKError`.

## Permission cache and authorization

`PermissionsClient` fetches `GET /authz/permissions/{userID}` with its service
bearer token, caches entries for two minutes by default, and single-flights
requests for the same user. A presented token with a different `permVer`
causes a fresh fetch.

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
request. `Client` combines verification, the local cache, and remote fallback;
its `allow` and `check` methods mirror the Go SDK names. Uppercase aliases
(`Get`, `Invalidate`, `Clear`, `Allow`, and `Check`) are also available for
callers porting Go code.

## Permission keys and ABAC

`Parse`/`Validate` enforce the `resource:action:scope` grammar, including the
server's `iam` scope rules. `*` matches one segment. A leading `!` marks a deny
permission; `Match` preserves the deny bit, while authorization decisions give
a matching deny precedence over matching allows.

`CompileCondition` implements the documented zero-dependency condition subset:
member access on `subject`, `resource`, and `request`, comparisons, boolean
operators, `in`, and string/number/boolean/array literals. `resource.attrs`
indexing and comparisons involving `request.time` are supported. Conditions
are limited to 4 KiB and a bounded AST; unsupported syntax is a compile error,
and evaluation errors deny access.

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

## Permission invalidation events

`SubscribePermissions` listens to `iam.perm.changed`, `iam.user.disabled`, and
`iam.role.updated`. Event payloads may contain `user_ids` or `user_id`; affected
cache entries are invalidated before the optional handler runs. Pass a NATS URL
when the optional `nats` peer is installed, or pass a test/application source
implementing `subscribe(subject, handler)`. An empty URL is a no-op. Requesting
a non-empty URL without the optional peer raises `NATSDependencyError` at
subscription time. `PermissionSubscription.close()` is idempotent.
