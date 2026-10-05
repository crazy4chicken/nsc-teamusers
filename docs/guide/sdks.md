# SDK usage guide

teamusers ships three SDKs that verify access tokens locally (EdDSA against a
cached JWKS document) and authorize with validated v2 permission snapshots.
Their existing live `/authz/check` fallback applies to snapshot transport/cache
failures; malformed or legacy snapshot protocols fail closed without downgrade.
No token introspection call is required on the hot path.

| SDK | Package | In-repo reference |
| --- | --- | --- |
| Go | `github.com/crazy4chicken/nsc-teamusers/sdk/go` | `sdk/go/README.md` |
| TypeScript | `teamusers-sdk` | `sdk/ts/README.md` |
| Python | `teamusers-sdk` | `sdk/python/README.md` |

All three expose the same four building blocks:

1. **Verifier** — signature, issuer, audience, expiry, and `perm_ver`
   validation with a lazily-fetched JWKS cache.
2. **Permissions client** — per-subject v2 snapshots keyed by the token's
   `perm_ver`; `perm.changed` events invalidate them, and cache TTL plus
   `valid_until` bound local staleness when events are unavailable.
3. **Middleware guards** — `Authenticate`, `Require`, `RequireFresh`
   (step-up), and `RejectImpersonated`.
4. **Event subscriptions** — NATS-driven JWKS refresh and permission cache
   invalidation.

## Setup

:::tabs key:sdk-lang variant:code

== Go

```go
import iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"

verifier := iam.NewVerifier(
	"https://iam.example.com",        // issuer base URL
	iam.WithAudience("orders"),       // your service's audience
	iam.WithJWKSMinRefreshInterval(time.Hour),
)
defer verifier.Close()

permissions := iam.NewPermissionsClient(
	"https://iam.example.com",
	iam.WithServiceToken(os.Getenv("TEAMUSERS_SERVICE_TOKEN")),
)

client := iam.NewClient(verifier, permissions)
```

== TypeScript

```ts
import { Client, PermissionsClient, Verifier } from "teamusers-sdk";

const verifier = new Verifier("https://iam.example.com", {
  audience: "orders",
  cacheTtlMs: 60 * 60 * 1000,
});

const permissions = new PermissionsClient("https://iam.example.com", {
  token: process.env.TEAMUSERS_SERVICE_TOKEN,
});

const client = new Client(verifier, permissions);
```

== Python

```python
from teamusers_sdk import (
    Authenticate,
    Client,
    PermissionsClient,
    RejectImpersonated,
    Require,
    RequireFresh,
    Verifier,
)

verifier = Verifier(
    "https://iam.example.com",
    audience="orders",
)

permissions = PermissionsClient(
    "https://iam.example.com",
    token=os.environ["TEAMUSERS_SERVICE_TOKEN"],
)

client = Client(verifier=verifier, permissions=permissions)
```

:::

Construction never touches the network. The first `Verify` fetches
`/.well-known/jwks.json`; later verifications reuse the cached keys and
re-fetch on unknown `kid` (subject to the minimum refresh interval).

## Verifying a token by hand

Use this when you are not behind HTTP middleware — gRPC interceptors, queue
consumers, WebSocket upgrades.

:::tabs key:sdk-lang variant:code

== Go

```go
claims, err := verifier.Verify(ctx, bearerToken)
if err != nil {
	// Verification failed: bad signature, issuer, audience, or expiry.
	return ErrUnauthenticated
}
fmt.Println(claims.Subject, claims.Team, claims.Kind)
```

== TypeScript

```ts
try {
  const claims = await verifier.verify(bearerToken);
  console.log(claims.subject, claims.team, claims.kind);
} catch (error) {
  if (error instanceof TokenVerificationError) {
    // bad signature, issuer, audience, or expiry
  }
  throw error;
}
```

== Python

```python
try:
    claims = verifier.verify(bearer_token)
    print(claims.subject, claims.team, claims.kind)
except TokenVerificationError:
    raise HTTPException(status_code=401)
```

:::


## Versioned permission snapshots

Every SDK requests `GET /authz/permissions/{userID}?version=2` using a
service-kind bearer. The endpoint rejects missing, legacy, or unknown versions
with HTTP 400 instead of returning unsafe flattened grants. Coordinate the
server cutover with the v2-aware SDK code update before relying on team-scoped
snapshots; the in-repo package versions remain `0.3.0` for this wire cutover.

The response shape is `{version:2,user_id,perm_ver,grants:[{key,condition?,team_id?}],valid_until?}`.
SDKs require exactly version 2, the matching non-empty `user_id`, a
non-negative integer `perm_ver`, well-typed grant keys and conditions, and an
optional RFC 3339 `valid_until`. Platform grants omit `team_id` or set it to
null; scoped grants carry a non-empty team ID. Unknown additive fields are
ignored, while all defined fields and their known shapes remain strict. Missing
or unsupported versions, malformed known fields, and expired `valid_until`
values are protocol failures: SDKs reject them and never downgrade or use a
live-check fallback. Unknown fields do not add security semantics; any future
security-semantic change requires an explicit snapshot version.

The optional `valid_until` is the earliest future membership or binding expiry
that affects the snapshot's grants. Each SDK caps snapshot-cache lifetime at
the earlier of its configured TTL and `valid_until`. This deadline covers
known future expiry, not a later membership or team-status mutation; those
changes rely on permission-version invalidation events or normal cache expiry.

Before matching a scoped grant, an SDK requires its `team_id` to equal the
non-empty `resource.team_id`. A requested `:team` key without that resource
field denies, even if a platform grant exists; a `:any` key in a team-bound
grant does not become platform access. Team status and membership changes bump
affected users' `perm_ver` and publish the existing `perm.changed` event.

## Authorizing a request

`Require` evaluates local ABAC conditions only after team applicability is
checked. The `Resource` you pass supplies the target context
(`resource.owner_id`, `resource.team_id`, `resource.attrs`); a team-scoped grant
is usable only for its own team, and a requested `:team` permission without a
`resource.team_id` denies.

:::tabs key:sdk-lang variant:code

== Go

```go
mux.Handle("POST /teams/{team}/documents/{id}/share",
	client.Middleware(
		client.Require("documents:share:team", func(r *http.Request) iam.Resource {
			return iam.Resource{
				TeamID: r.PathValue("team"),
				Attrs:  map[string]any{"document_id": r.PathValue("id")},
			}
		})(shareHandler),
	),
)
```

== TypeScript

```ts
// Middleware-composable form: returns a guard you can chain. Resource values
// come from your router/framework, not from the SDK's request shape.
const guard = Require(client, "documents:share:team", () => ({
  team_id: teamID,
  attrs: { document_id: documentID },
}));

const claims = await guard(request); // throws ForbiddenError with the deny reason
```

== Python

```python
# Direct form: raises ForbiddenError on deny.
claims = Require(
    client, request, claims,
    "documents:share:team",
    {"team_id": team_id, "attrs": {"document_id": document_id}},
)
```

:::

Denials carry a stable reason such as `no matching grant`, `condition_error`,
or `step_up_required`; a false condition simply excludes that grant, while an
applicable condition error fails authorization closed. Reasons are safe to log
but should not be echoed to end users verbatim.

## Step-up and impersonation guards

Two additional guards plug into the same middleware chain:

- **`RequireFresh(maxAge)`** accepts a token with a positive `auth_time` or
  `step_up_time` within `maxAge`; timestamps up to 30 seconds in the future are
  accepted. Older tokens without `step_up_time` can still pass using a recent
  `auth_time`; otherwise the guard returns `step_up_required`.
- **`RejectImpersonated()`** rejects tokens minted by
  `POST /impersonations` (`imp=true`) — put it in front of anything a support
  admin must never do as the user (billing changes, data export to third
  parties). The service already blocks impersonated tokens from every `/me`
  mutation; this guard extends the same posture to your own endpoints.

Impersonation tokens cannot use MFA-only step-up or bypass `RequireFresh` with
`step_up_time`; keep `RejectImpersonated()` for handlers that must reject them.


:::tabs key:sdk-lang variant:code

== Go

```go
handler := client.Middleware(
	client.RejectImpersonated()(
		client.RequireFresh(10 * time.Minute)(
			client.Require("billing:payout:any", nil)(payoutHandler),
		),
	),
)
```

== TypeScript

```ts
const claims = await Authenticate(request, verifier);
await RejectImpersonated()(request, claims);
await RequireFresh(10 * 60 * 1000)(request, claims);
await Require(client, "billing:payout:any")(request, claims);
```

== Python

```python
claims = Authenticate(request, verifier)
RejectImpersonated()(request, claims)
RequireFresh(10 * 60)(request, claims)
Require(client, request, claims, "billing:payout:any")
```

:::

Impersonated sessions are also visible to your own audit trail: `claims.Actor`
(Go) / `claims.actor` (TypeScript) / `claims.actor` (Python) holds the admin's
user ID when `claims.Impersonated` (Go) / `claims.impersonated` is true.

## Keeping caches fresh with events

Without events, a local permission entry can remain stale until the earlier of
its configured cache TTL or v2 `valid_until`; the latter bounds known future
membership/binding expiry only. When delivered, `perm.changed` invalidates the
user's snapshot, while `team.updated` remains the team-status lifecycle event.

:::tabs key:sdk-lang variant:code

== Go

```go
// Requires building with -tags nats.
keySub, err := verifier.SubscribeKeyRotations(os.Getenv("TEAMUSERS_NATS_URL"))
if err != nil {
	return err
}
defer keySub.Close()

permSub, err := client.SubscribePermissions(
	os.Getenv("TEAMUSERS_NATS_URL"),
	func(userIDs []string) {
		slog.Info("permissions invalidated", "users", userIDs)
	},
)
if err != nil {
	return err
}
defer permSub.Close()
```

== TypeScript

```ts
import { subscribeKeyRotations, subscribePermissions } from "teamusers-sdk";

const keySub = await subscribeKeyRotations(verifier, process.env.TEAMUSERS_NATS_URL);
const permSub = await subscribePermissions(permissions, process.env.TEAMUSERS_NATS_URL);
// ... on shutdown:
await keySub?.close();
await permSub?.close();
```

== Python

```python
from teamusers_sdk import events

key_sub = events.subscribe_key_rotations(verifier, nats_url)
perm_sub = events.subscribe_permissions(permissions, nats_url)
# ... on shutdown:
key_sub.close()
perm_sub.close()
```

:::

Subscriptions remain optional: without NATS the SDKs continue using TTL-based
cache expiry, clamped by `valid_until`. Event delivery tightens revocation when
messages arrive but is not itself a correctness guarantee.

## Choosing local vs. remote authorization

The default Go `Client.Allow`, TypeScript `Client.allow`, and Python
`PermissionsClient.allow` evaluate against validated v2 snapshots; the Go and
TypeScript `Client` and Python client retain their existing live `/authz/check`
fallback for snapshot transport/cache failures. The TypeScript
`PermissionsClient.allow` method itself is local-only. Malformed snapshots,
unsupported or legacy versions, expired `valid_until`, and a `perm_ver` mismatch
fail closed without fallback (`permission version mismatch` for the latter).
Unknown additive fields are ignored when the known v2 schema is valid. Use
explicit remote-only mode when every decision must query `/authz/check`:

:::tabs key:sdk-lang variant:code

== Go

```go
client := iam.NewClient(verifier, permissions, iam.WithRemoteOnly(true))
```

== TypeScript

```ts
const client = new Client(verifier, permissions, { remoteOnly: true });
```

== Python

```python
client = Client(verifier=verifier, permissions=permissions, remote_only=True)
```

:::

Remote-only mode costs one HTTP round trip per authorization decision; keep it
off for high-throughput read paths.

## Error handling summary

| Layer | Go | TypeScript | Python |
| --- | --- | --- | --- |
| Bad token | plain `error` from `Verify` | `TokenVerificationError` | `TokenVerificationError` |
| No credentials | 401 via middleware | `UnauthorizedError` | `UnauthorizedError` |
| Permission denied | 403 via middleware | `ForbiddenError` | `ForbiddenError` |
| Step-up required | 403 `step_up_required` | `ForbiddenError("step_up_required")` | `ForbiddenError("step_up_required")` |
| Impersonated rejected | 403 `impersonation_forbidden` | `ForbiddenError("impersonation_forbidden")` | `ForbiddenError("impersonation_forbidden")` |

The TypeScript and Python error types carry a stable `code` field; match on
the code, never on the message text. The Go SDK returns plain errors — treat
any `Verify` failure as unauthenticated and rely on middleware status codes.

Treat only the exact `403 step_up_required` detail as a freshness denial. Other
`401` or `403` responses, `password_change_required`, and the initial login
`mfa_required` challenge require their own authentication or authorization
flows. SDK guards check token claims locally; they do not perform step-up or
rotate a caller's access/refresh pair. See the [security guide](/guide/security)
for the authenticated step-up flow and safe token-pair replacement.
