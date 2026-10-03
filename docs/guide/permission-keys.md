---
title: Permission keys
outline: 2
---

# Permission keys

Every grant in teamusers is a single string key with a strict three-segment
grammar:

```text
[!]resource:action:scope
```

Exactly three `:`-separated segments are required; an optional leading `!`
makes the key an explicit deny. Keys are data — they are validated at write
time when registered or assigned, and runtime checks parse the same grammar.

## The three segments

### `resource` — what is being accessed

Names the target resource type or namespace: `orders`, `docs`,
`invoice_items`. The IAM admin surface itself is addressed with the reserved
resource `iam` (see [iam keys](#iam-keys) below).

- Must start with a lowercase letter; may continue with lowercase letters,
  digits, `_`, `.`, `-`.
- **Never wildcards.** A `*` resource segment is rejected by validation and
  can never match.

### `action` — what is being done

The verb applied to the resource: `read`, `write`, `delete`, `approve`. For
`iam` keys the action names the administrative area (`users`, `teams`,
`roles`, ...).

- Same character set as `resource`, except `.` is not allowed.
- A whole-segment `*` is the only wildcard form: `orders:*:team` grants every
  action on team orders.

### `scope` — how far the grant reaches

The breadth of the grant relative to the calling subject. Exactly one of:

| Scope | Reaches |
| --- | --- |
| `own` | Records owned by the subject itself (`docs:read:own`) |
| `team` | Records belonging to the subject's team (`orders:refund:team`) |
| `any` | Platform-wide, regardless of owner or team (`users:invite:any`) |
| `*` | Wildcard covering every scope with one key |

Which scope a check actually enforces is decided by the service handling the
request — see [matching rules](#matching-rules) before choosing.

## The deny prefix

Prefixing any valid key with `!` creates a deny grant: `!orders:delete:team`.
Deny keys use the identical grammar, are stored with the prefix, and must be
registered exactly as assigned (including the `!`). **A matching deny always
wins**, even when a matching allow exists and no matter how broad the allow
is. Use denies to carve exceptions out of wide grants:

```text
orders:*:any        # everything on orders
!orders:delete:any  # ... except deletion
```

## Matching rules

Matching is **segment-wise** (`internal/domain/matcher.go`):

- Each grant segment matches the request segment if it is equal or `*`. A
  wildcard covers exactly one segment value and never crosses a `:` boundary.
- Only the `action` and `scope` segments accept `*` in a registered key.
- **There is no scope subsumption.** An `orders:read:any` grant does not
  satisfy an `orders:read:team` request; the grant scope must equal the
  request scope or be `*`. A service that enforces both own-record and
  team-wide access checks each operation at the scope that reflects its
  breadth, and administrators grant the matching scopes (or a `:*` scope).
- When several grants match one request, the narrower scope wins
  (`own` > `team` > `any` > `*`), and a matching deny beats every allow.

The effective set behind every check is: direct bindings ∪ group bindings →
roles → permission keys, minus expired bindings, disabled users, and grants
whose ABAC condition fails. `/authz/check` and the SDK local resolvers share
these rules.

## `iam:` keys

The `iam` resource addresses the administrative plane and has extra
validation (`internal/domain/permission.go`):

- `iam:<area>:any` is valid for every area.
- `iam:<area>:team` is valid **only** for the team-scoped areas `teams`,
  `groups`, `roles`, and `bindings`; team keys for other areas are rejected
  at write time.
- `iam:*:any` is the platform wildcard covering every current and future
  `:any` admin key (but no `:team` keys).

How these keys gate admin routes, team-target resolution, and team-scoped
mutation restrictions is documented in
[Administrative permission scopes](./permissions).

## Registering keys

Keys must be registered (`POST /permissions`, `iam:permissions:any`) exactly
as they are assigned, including any `!` prefix. Registration validates the
full grammar, so invalid segments, missing segments, and misplaced wildcards
fail at write time rather than at check time. Role assignments
(`PUT /roles/{id}/permissions`) reference registered keys.

## Examples

| Key | Meaning |
| --- | --- |
| `docs:read:own` | Read one's own documents |
| `docs:*:team` | Every action on team documents |
| `orders:read:*` | Read orders at any breadth |
| `!orders:export:any` | Deny order exports platform-wide (wins over allows) |
| `iam:roles:team` | Administer roles within one's own team |
| `iam:users:any` | Administer users platform-wide |
