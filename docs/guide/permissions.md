---
title: Administrative permission scopes
outline: 2
---

# Administrative permission scopes

Administrative access is controlled by `iam:<area>:<scope>` keys. The `any`
scope is a platform grant and is valid for every administrative area. The
`team` scope is valid only for `teams`, `groups`, `roles`, and `bindings`:

- `iam:teams:any` / `iam:teams:team`
- `iam:groups:any` / `iam:groups:team`
- `iam:roles:any` / `iam:roles:team`
- `iam:bindings:any` / `iam:bindings:team`
- `iam:policies:any` — Manage password and MFA policies. This is security-critical:
  granting it can weaken any account's password requirements.
- `iam:*:any` — Platform wildcard for every current and future
  `iam:<area>:any` permission.

`iam:*:any` covers future IAM areas at the `:any` scope; it does not grant
team-scoped or other non-`:any` keys. The `iam:policies:any` risk is an
accepted administrative trade-off, so grant it only to trusted administrators.

`users`, `audit`, `sessions`, `permissions`, and `policies` are platform-only
areas. Their `:team` keys are rejected by permission-key validation. A
team-scoped admin therefore cannot use a team grant to access those areas; it
needs the matching `:any` grant.

Grant applicability also depends on the role binding, not only the permission-key
scope. A non-null binding `team_id` keeps every grant from that binding confined
to the matching active team resource, even when the key ends in `:any`; it never
becomes platform access. A `team_id: null` platform binding remains independent
of team membership. Disabling a team suppresses its scoped grants, while
independent platform grants can still administer that team.

For a team baseline, `POST /bindings` creates at most one binding per team with
`subject_kind=team`, `subject_id` equal to `team_id`, and a role that is either
platform-scoped or owned by that same team. Foreign-team roles are rejected.
A baseline may carry a condition and allow or deny permissions but cannot carry
`expires_at`; ordinary user/group binding expiry remains supported.

## Resolution

For the target resource, the middleware resolves all applicable grants,
including platform bindings and bindings scoped to the matching active team.
No role or grant source has priority: a matching explicit deny overrides every
matching allow across those applicable sources, then the default is deny.
`:any`, `:team`, and `:own` remain distinct permission-key scopes; see
[Permission keys](./permission-keys) for the unchanged matching grammar.

`GET /me/permissions` is a separate user-bearer endpoint that keeps its flat
`permissions` list. It omits each grant's team (`team_id`) and target-resource
context, so it is informational/UI display only—not authorization evidence or
a final allow/deny result. Enforce access with contextual `POST /authz/check`,
or evaluate v2 snapshot grants against the actual resource, including
`team_id`.

A grant from a team-scoped binding applies only when the target resource has the
same `team_id` as the binding and that team is active. This applies to user, group,
and team-baseline bindings alike. A requested `:team` permission without a
`resource.team_id` fails closed. A team baseline uses `subject_kind=team` with
`subject_id` equal to its `team_id`; it is inherited by any user with at least one
unexpired membership in any group in that active team. Removing or expiring the
user's last such membership removes baseline eligibility. Membership in multiple
groups does not create extra baseline bindings.

Platform bindings with `team_id: null` remain available without team membership,
but a platform allow does not bypass a matching team deny for an eligible
member. For a user with an active membership in the target team, applicable
platform and team grants are resolved together; the team deny defeats a
matching platform allow for that team's resource. A user outside the active
team, including a platform administrator without membership, does not inherit
that team's baseline deny and retains independent platform grants. Disabled
teams suppress scoped grants but not independent platform grants.

Admin conditions receive this context:

- `subject.id` and `subject.kind` (`user`)
- `resource.team_id` for the resolved target team and an empty `resource.owner_id`
- `request.time` for the current request time

A condition that evaluates false excludes only that grant. A compile or evaluation
error on an applicable grant rejects the whole authorization rather than being
ignored; `/authz/check` returns `allow=false` with reason `condition_error`.
Unknown targets return `404`, and a request without a target cannot use a `:team`
grant.

## Team baseline binding requests

These examples assume team `01J8Z3TEAM000000000000001` and its role
`01J8Z3ROLE000000000000001` already exist, and both permission keys are
registered. Assign the team-owned role its allow and deny keys first:

`PUT /roles/01J8Z3ROLE000000000000001/permissions`

```json
{"permission_keys":["orders:read:team","!orders:delete:team"]}
```

Create the team's one baseline by setting `subject_id` and `team_id` to the same
team ID. The optional condition below is valid for the request context; omit
`condition` for an unconditional baseline. Do not send `expires_at`.

`POST /bindings`

```json
{
  "role_id": "01J8Z3ROLE000000000000001",
  "subject_kind": "team",
  "subject_id": "01J8Z3TEAM000000000000001",
  "team_id": "01J8Z3TEAM000000000000001",
  "condition": "resource.team_id == \"01J8Z3TEAM000000000000001\""
}
```

`team_id` may instead be omitted and inferred. A second baseline create for
that team returns `409`; the role must be platform-scoped or owned by the same
team, and a foreign-team role is rejected. Read it with the existing cursor page
or remove it with the existing item route:

```http
GET /bindings?subject_kind=team&subject_id=01J8Z3TEAM000000000000001
DELETE /bindings/01J8Z3BIND000000000000001
```

PATCH replaces only `role_id` and/or `condition`; omitted fields stay unchanged.
The replacement role must be platform-scoped or owned by the baseline team;
foreign-team roles are rejected.

`PATCH /bindings/01J8Z3BIND000000000000001`

```json
{
  "role_id": "01J8Z3ROLE000000000000002",
  "condition": "resource.attrs[\"region\"] == \"us-east-1\""
}
```

Send `{"condition":null}` to clear the condition. `subject_kind`,
`subject_id`, `team_id`, and `expires_at` cannot be changed by PATCH.

`iam:bindings:team` may create a baseline for its active team, list a team or
group target, or mutate bindings only in that active team. User-wide binding
lists require independent platform `iam:bindings:any`. That platform grant can
maintain a disabled team; its scoped grants are suppressed.

`GET /bindings` uses the same permission scopes without step-up. Mutating
`POST /bindings`, `PATCH /bindings/{id}`, and `DELETE /bindings/{id}` requires a
user bearer with recent `auth_time` or `step_up_time`; see the
[fresh authentication](/guide/security#fresh-authentication-for-administrative-mutations).

An applicable baseline deny wins a matching allow for that team's resource,
including a matching platform allow held by an eligible team member. It does
not affect users outside the active team or a platform administrator who does
not inherit the baseline. There is no role/source priority.

## Deny permissions

Prefix a permission key with `!` to create an explicit deny, for example
`!iam:teams:any` or `!orders:delete:team`. Deny keys use the same grammar as
allow keys and are stored with the `!` prefix. A matching deny is evaluated in
the same grant set as its allow keys and always wins, even when a matching
allow is also present. Wildcards continue to match only within one permission
segment. This applies to `/authz/check` and to administrative `:any` and
`:team` middleware checks.

A deny from a team baseline is considered only for an active member and a
matching resource team. It does not affect users outside that team or a
platform administrator who does not inherit the baseline. If an eligible
member also has a matching independent platform allow, the baseline deny
still wins; no source priority bypasses it.

Permission keys must be registered exactly as they are assigned, including the
`!` prefix.

## Team-scoped role mutation restrictions

When a request is authorized by an `iam:<area>:team` grant, the middleware
records the grant as team-scoped for the route handler. Team-scoped admins:

- May attach only `:team` permission keys when replacing role permissions.
  Keys with `:any`, `:own`, or `:*` scopes are rejected with `403`, and the
  role's existing permissions are left unchanged.
- May not change a role's `team_id`. A PATCH that includes a team change is
  rejected with `403`; name-only PATCH requests remain allowed in the role's
  existing team.

Platform `:any` grants are not subject to these restrictions.
The write restriction above does not broaden the resulting grant: if a platform
administrator assigns a `:any` permission to a team-owned role, a team-scoped
binding still limits that grant to its matching active team resource.

`GET /roles/{id}/permissions` lists the assigned permission keys in ascending
order. Pass `limit` (positive, default 100, capped at 1000) and the previous
`next_cursor` as `cursor`. A full page returns its last key as `next_cursor`;
short pages return an empty cursor, and an empty role returns
`{"items":[],"next_cursor":""}`. Authorization uses `iam:roles:any` or an
applicable `iam:roles:team` grant for the role's team; reads do not require
step-up authentication.


Target teams are resolved as follows:

- `/teams/{id}` uses the path ID. `/teams` collections and `POST /teams` have
  no target and require `:any`.
- `/groups/{id}` and `/groups/{id}/members/...` use the group's `team_id`.
  `POST /groups` uses the request body's `team_id`; a collection query with
  `team_id` uses that team.
- `/roles/{id}` and `/roles/{id}/permissions` use the role's `team_id`.
  `POST /roles` uses the request body's `team_id`; platform roles require
  `:any`.
- `GET /bindings` with `subject_kind=team` uses `subject_id` as the target team;
  a group subject uses the group's team. Team-scoped listing is available only
  for an active team; user-wide listing requires platform `iam:bindings:any`.
- `POST /bindings` for a team baseline uses `subject_id` as the target team and
  requires `team_id` to match if supplied. Existing user/group binding creation
  continues to resolve the role's team. Team-scoped admins need an active target
  team; platform `iam:bindings:any` can manage disabled teams.
- `PATCH /bindings/{id}` and `DELETE /bindings/{id}` use the existing binding's
  team. `iam:bindings:team` is limited to that active team; independent platform
  `iam:bindings:any` can maintain a disabled team.


An unknown target is returned as `404` before a team grant is evaluated. A
request with no resolvable team target cannot be authorized by `:team` and
returns `403`. Platform `:any` grants remain independent and continue to the
normal route handler, which supplies that handler's usual response for the
resource.
