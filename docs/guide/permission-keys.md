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

### `scope` — request scope

The scope segment is part of the requested permission key; it is not a numeric
rank or a binding source. Exactly one of:

| Scope | Key convention |
| --- | --- |
| `own` | A request explicitly checked at `:own` scope; the service determines which records are owned by the subject. |
| `team` | A request explicitly checked at `:team` scope; the service supplies the target team context. |
| `any` | A request explicitly checked at `:any` scope. It is platform-wide only when the grant comes from a platform-scoped binding. |
| `*` | A wildcard matching any one scope segment. |

A binding's team scope is independent of the permission-key scope: a grant from a
team-scoped binding stays limited to its matching active team resource even when
its key ends in `:any`. See [matching rules](#matching-rules) before choosing a key.

## The deny prefix

Prefixing any valid key with `!` creates a deny grant: `!orders:delete:team`.
Deny keys use the identical grammar, are stored with the prefix, and must be
registered exactly as assigned (including the `!`). **A matching deny always
wins**, even when a matching allow exists and no matter how broad the allow
is. Use denies to carve exceptions out of wide grants:

```text
orders:*:any        # every action on an :any request; binding scope still applies
!orders:delete:any  # ... except deletion at that request scope
```

## Matching rules

Matching is **segment-wise** (`internal/domain/matcher.go`):

- Each grant segment matches the request segment if it is equal or `*`. A
  wildcard covers exactly one segment value and never crosses a `:` boundary.
- Only the `action` and `scope` segments accept `*` in a registered key.
- There is no scope containment or ranking: `:any`, `:team`, and `:own` do not
  imply one another. A `*` scope segment matches each requested scope as a
  wildcard, but is not a priority winner.
- After binding/team applicability and condition evaluation, any matching deny
  wins every matching allow; otherwise any matching allow grants access, and no
  match defaults to deny. Grant source and role have no priority.
- `/authz/check` reports every applicable key that matched and passed its
  condition in `matched`, sorted lexicographically; the list does not select a
  priority winner. A false condition excludes only that grant, so no other match
  leaves the default reason `no matching grant`. An error evaluating an
  applicable condition rejects the whole check with `allow=false`, an empty
  `matched` list, and reason `condition_error`.

The effective set behind authorization checks includes direct user, group, and
team-baseline bindings expanded to permission keys. Team baselines apply to any
user with at least one unexpired membership in a group in that active team;
disabled teams suppress scoped grants. Expired bindings/memberships and disabled
users are excluded. `/authz/check` and the SDK local resolvers use the same
permission-key matching and deny-overrides rules.

## `iam:` keys

The `iam` resource addresses the administrative plane and has extra
validation (`internal/domain/permission.go`):

- `iam:<area>:any` is valid for every area.
- `iam:<area>:team` is valid **only** for the team-scoped areas `teams`,
  `groups`, `roles`, and `bindings`; team keys for other areas are rejected
  at write time.
- `iam:*:any` matches every current and future `:any` admin key but no
  `:team` key; it is platform-wide only when inherited from a platform binding.

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
| `!orders:export:any` | Deny exports for a matching `:any` request; a team binding remains team-scoped |
| `iam:roles:team` | Administer roles for the matching team resource |
| `iam:users:any` | Administer users platform-wide only from a platform-scoped binding |
