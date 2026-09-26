# teamusers Go SDK

The package at `github.com/crazy4chicken/nsc-teamusers/sdk/go` verifies teamusers Ed25519 (`EdDSA`) access
tokens and provides permission caching, local ABAC evaluation, middleware, and
authoritative authorization checks. Permission caches use the token's
`perm_ver` claim and can be invalidated by NATS events when built with the
optional `nats` build tag.

## Install

From a consuming Go module:

```sh
go get github.com/crazy4chicken/nsc-teamusers/sdk/go
```

Import the package as `iam`:

```go
import iam "github.com/crazy4chicken/nsc-teamusers/sdk/go"
```

## Verification

`NewVerifier` is lazy: construction does not contact the issuer. `Verify`
fetches and caches `/.well-known/jwks.json` as needed, then validates the EdDSA
signature, issuer, expiration, exactly one audience, subject, subject kind, and
permission version.

```go
ctx := context.Background()
verifier := iam.NewVerifier(
	"https://iam.example.com",
	iam.WithIssuer("teamusers"),
	iam.WithAudience("orders"),
	iam.WithHTTPClient(http.DefaultClient),
	iam.WithJWKSMinRefreshInterval(time.Hour),
)
defer verifier.Close()

claims, err := verifier.Verify(ctx, accessToken)
if err != nil {
	// Reject the request as unauthenticated.
	return err
}
fmt.Println(claims.Subject, claims.Kind, claims.PermVer)
```

`WithIssuer` and `WithAudience` default to `"teamusers"`. The issuer base URL
controls JWKS retrieval and is independent from the expected issuer claim.
`WithHTTPClient` supplies the transport for JWKS and permission requests, and
`WithJWKSMinRefreshInterval` controls the minimum JWKS refresh interval.
`Close` stops background JWKS workers and is safe to call more than once.

### Claims

`Verify` returns a `Claims` value after all checks succeed.

| Field | Type | Meaning |
| --- | --- | --- |
| `Subject` | `string` | Non-empty user or service subject (`sub`) |
| `Team` | `string` | Optional team claim; empty when absent |
| `Kind` | `string` | Subject kind: `"user"` or `"service"` |
| `PermVer` | `int64` | Non-negative permission version (`perm_ver`) |
| `Audience` | `string` | The single verified JWT audience (`aud`) |
| `Expiry` | `time.Time` | Verified expiration time (`exp`) |

## Permission cache and authorization

`PermissionsClient` fetches `GET /authz/permissions/{userID}` with a service
bearer token and caches each user's `PermissionEntry` for two minutes by
default. Construct it with `NewPermissionsClient`:

```go
permissions := iam.NewPermissionsClient(
	"https://iam.example.com",
	iam.WithServiceToken(os.Getenv("TEAMUSERS_SERVICE_TOKEN")),
	iam.WithHTTPClient(http.DefaultClient),
)
entry, err := permissions.Get(ctx, claims.Subject, claims.PermVer)
if err != nil {
	return err
}
_ = entry.Grants
```

`WithTokenSource` accepts `func() (string, error)` for rotating service
credentials and takes precedence over `WithServiceToken`. `WithPermissionsTTL`
(or its `WithTTL` alias) changes the in-process TTL. A cached entry is reused
only while its TTL is valid and its `PermVer` equals the token's `PermVer`, so a
`perm_ver` change automatically causes a fresh request.

Use `Invalidate` for selected users and `Clear` for the whole cache:

```go
permissions.Invalidate(claims.Subject)
permissions.Clear()
```

`InvalidatePermissions` is an explicit alias for `Invalidate`.

### Client

`Client` combines verification, local permission evaluation, and remote
fallback:

```go
client := iam.NewClient(verifier, permissions)

allowed, reason := client.Allow(ctx, claims, "orders:read:team", iam.Resource{
	TeamID: "team_1",
})
if !allowed {
	return errors.New(reason)
}
```

`Allow` evaluates the local cached grants first. If the permission cache cannot
be fetched, it falls back to the authoritative `POST /authz/check` endpoint.
`Check` always performs that authoritative remote check and returns
`(allowed, reason, error)`.

`Middleware` verifies a bearer token and stores the resulting `Claims` in the
request context. `Require` creates an HTTP middleware guard that derives a
`Resource` for each request:

```go
next := http.HandlerFunc(handleOrder)
protected := client.Middleware(
	client.Require("orders:read:team", func(r *http.Request) iam.Resource {
		return iam.Resource{TeamID: r.PathValue("teamID")}
	})(next),
)
```

Use `ClaimsFromContext` inside downstream handlers to retrieve verified claims.
`WithRemoteOnly(true)` makes `Client.Allow` skip the local cache and use the
authoritative remote check every time:

```go
remoteClient := iam.NewClient(verifier, permissions, iam.WithRemoteOnly(true))
```

## ABAC conditions

`CompileCondition` compiles a condition against the fixed `Context` schema.
Compilation errors are returned. `CompiledCondition.Eval` and
`CompiledCondition.EvalWithContext` fail closed: runtime, type, and context
cancellation errors evaluate to `false`. A nil or empty compiled condition
allows the grant. `Evaluate` is an alias for `Eval`.

```go
condition, err := iam.CompileCondition(
	`subject.id == "user_1" && resource.attrs["tier"] == "gold"`,
)
if err != nil {
	return err
}

values := iam.Context{
	Subject:  iam.Subject{ID: claims.Subject, Kind: claims.Kind},
	Resource: iam.Resource{TeamID: "team_1", Attrs: map[string]any{"tier": "gold"}},
	Request:  iam.Request{Time: time.Now()},
}
if !condition.Eval(values) {
	return errors.New("condition denied")
}
if !condition.EvalWithContext(ctx, values) {
	return errors.New("condition denied or context cancelled")
}
```

The condition schema exposes only these nested members:

| Context member | Fields |
| --- | --- |
| `subject` | `id`, `kind` |
| `resource` | `owner_id`, `team_id`, `attrs` |
| `request` | `time` |

The Go field names are `Subject`, `Resource`, and `Request`; nested values use
`Subject.ID`, `Subject.Kind`, `Resource.OwnerID`, `Resource.TeamID`,
`Resource.Attrs`, and `Request.Time`.

## Permission keys and deny semantics

Permission keys use the `resource:action:scope` grammar. `Parse` accepts an
optional leading `!`, stores it in `Permission.Deny`, and validates the
remaining three segments. `Permission.String` preserves the marker, so valid
keys round-trip:

```go
deny, err := iam.Parse("!orders:delete:own")
if err != nil {
	return err
}
fmt.Println(deny.Deny, deny.String()) // true !orders:delete:own
```

`*` matches one segment only; it never crosses a colon boundary. The deny
marker is not a fourth wildcard segment. `Match` and `MatchKeys` preserve the
permission identity while applying the same segment rules. During
`Client.Allow`, matching deny grants are evaluated against the requested
segments and take precedence over every matching allow grant, regardless of
grant order. A deny whose condition evaluates to false counts as no deny and
allows a condition-passing allow grant to proceed.

## Permission invalidation events

`SubscribePermissions` subscribes a `PermissionsClient` (or its `Client`
delegate) to permission-affecting events. A handler receives the affected user
IDs after the cache entries are invalidated:

```go
subscription, err := permissions.SubscribePermissions(natsURL, func(userIDs []string) {
	log.Printf("invalidated permissions for %v", userIDs)
})
if err != nil {
	return err
}
if subscription != nil {
	defer subscription.Close()
}
```

NATS support is compiled with the `nats` build tag:

```sh
go build -tags nats ./sdk/go
```

Without the tag, an empty NATS URL is a guarded no-op and a non-empty URL
returns an error explaining that NATS support is disabled. `Close` is safe to
call more than once.

## Further reading

See the [permissions guide](https://crazy4chicken.github.io/nsc-teamusers/guide/permissions)
for the server permission grammar, scopes, grants, conditions, and
invalidation behavior.
