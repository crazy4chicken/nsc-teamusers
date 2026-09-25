# Administrative permission scopes

Administrative access is controlled by `iam:<area>:<scope>` keys. The `any`
scope is a platform grant and is valid for every administrative area. The
`team` scope is valid only for `teams`, `groups`, `roles`, and `bindings`:

- `iam:teams:any` / `iam:teams:team`
- `iam:groups:any` / `iam:groups:team`
- `iam:roles:any` / `iam:roles:team`
- `iam:bindings:any` / `iam:bindings:team`

`users`, `audit`, `sessions`, and `permissions` are platform-only areas. Their
`:team` keys are rejected by permission-key validation. A team-scoped admin
therefore cannot use a team grant to access those areas; it needs the matching
`:any` grant.

## Resolution

The middleware checks `iam:<area>:any` first. If that grant does not resolve,
it checks `iam:<area>:team` only for the team that owns the target resource.
Role bindings must be active and unconditional for these checks, and the
binding's team must match the target team.

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

Target teams are resolved as follows:

- `/teams/{id}` uses the path ID. `/teams` collections and `POST /teams` have
  no target and require `:any`.
- `/groups/{id}` and `/groups/{id}/members/...` use the group's `team_id`.
  `POST /groups` uses the request body's `team_id`; a collection query with
  `team_id` uses that team.
- `/roles/{id}` and `/roles/{id}/permissions` use the role's `team_id`.
  `POST /roles` uses the request body's `team_id`; platform roles require
  `:any`.
- `POST /bindings` resolves the role named by the request body and uses the
  role's team. Binding item routes resolve the existing binding's `team_id`.

An unknown target is returned as `404` before a team grant is evaluated. A
request with no resolvable team target cannot be authorized by `:team` and
returns `403`. Platform `:any` grants continue to the normal route handler,
which supplies that handler's usual response for the resource.
