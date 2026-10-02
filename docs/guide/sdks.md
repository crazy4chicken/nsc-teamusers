# SDK usage guide

teamusers ships three SDKs that verify access tokens **locally** (EdDSA
against a cached JWKS document) and authorize requests against a cached
permission set, falling back to the authoritative `/authz/check` endpoint when
needed. No token introspection call is required on the hot path.

| SDK | Package | In-repo reference |
| --- | --- | --- |
| Go | `github.com/crazy4chicken/nsc-teamusers/sdk/go` | `sdk/go/README.md` |
| TypeScript | `teamusers-sdk` | `sdk/ts/README.md` |
| Python | `teamusers-sdk` | `sdk/python/README.md` |

All three expose the same four building blocks:

1. **Verifier** — signature, issuer, audience, expiry, and `perm_ver`
   validation with a lazily-fetched JWKS cache.
2. **Permissions client** — per-subject permission snapshots keyed by the
   token's `perm_ver` claim, so a stale cache entry can never outlive a
   revocation.
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

## Authorizing a request

`Require` combines cache lookup, local ABAC condition evaluation, and a remote
fallback. The `Resource` you pass is what ABAC conditions match against
(`resource.owner_id`, `resource.team_id`, `resource.attrs`).

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

Denials carry the reason string from the server (`expired binding`, failed
condition, missing grant), which is safe to log but should not be echoed to
end users verbatim.

## Step-up and impersonation guards

Two additional guards plug into the same middleware chain:

- **`RequireFresh(maxAge)`** rejects tokens whose `auth_time` is older than
  `maxAge` with `step_up_required` — put it in front of payout, credential, or
  admin-adjacent handlers so a stolen long-lived token cannot perform them.
- **`RejectImpersonated()`** rejects tokens minted by
  `POST /impersonations` (`imp=true`) — put it in front of anything a support
  admin must never do as the user (billing changes, data export to third
  parties). The service already blocks impersonated tokens from every `/me`
  mutation; this guard extends the same posture to your own endpoints.

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

Without events, revocations propagate within
`min(access_token_TTL, cache_TTL)`. With the optional NATS subscriptions the
window narrows to seconds: `key.rotated` forces a JWKS refresh and the
`perm.changed`/`user.*`/`team.*` subjects invalidate permission snapshots.

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

Subscriptions are optional everywhere: if NATS is unreachable the SDKs keep
working on TTL-based expiry. Treat them as a tightening knob, not a
correctness requirement.

## Choosing local vs. remote authorization

The default `Client` evaluates locally against the cached permission snapshot
(fetched per subject and keyed by the token's `perm_ver`), and falls back to
the authoritative `/authz/check` endpoint only when the snapshot cannot be
fetched — a `perm_ver` mismatch fails closed rather than serving a stale
grant. Pass the `remoteOnly` option (`remote_only` in Python) when your
service must never rely on a cached decision — for example a settlement
service where a minutes-old permission grant is unacceptable:

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
