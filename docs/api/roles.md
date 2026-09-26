# Roles API

## Use cases

Use roles to package registered permission keys into reusable platform-wide or team-scoped grants. An administrator can create a role, replace its permission set, then bind it to users or groups.

## Key concepts

- A role's `team_id` is nullable on input: send JSON `null` for platform scope or a ULID for team scope. Platform-scoped responses omit `team_id` because the Go model uses `omitempty`.
- `PUT /roles/{id}/permissions` replaces the entire set. `permission_keys` is canonical; `permissions` remains an accepted legacy alias.
- Permission keys must already be registered and use `resource:action:scope` grammar.
- Role mutations bump affected users' `perm_ver`; see the [API permissions](./permissions.md) page and [permissions guide](../guide/permissions.md) for cache and grant semantics.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/roles?team_id=&cursor=&limit=` | List platform/team roles. |
| POST | `/roles` | Create a role. |
| GET | `/roles/{id}` | Read a role. |
| PATCH | `/roles/{id}` | Rename or change scope. |
| DELETE | `/roles/{id}` | Delete a role. |
| PUT | `/roles/{id}/permissions` | Replace role permissions. |

## Create a role and attach keys

```sh
BASE=http://localhost:8080
ROLE=$(curl -sS -X POST "$BASE/roles" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"team_id":"<team-id>","name":"operator"}')
ROLE_ID=$(printf '%s' "$ROLE" | jq -r .id)
curl -sS -X PUT "$BASE/roles/$ROLE_ID/permissions" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"permission_keys":["orders:read:team","orders:update:own"]}'
curl -sS "$BASE/roles/$ROLE_ID" -H "Authorization: Bearer $ADMIN_TOKEN"
```

List roles in a team, then rename one:

```sh
curl -sS "$BASE/roles?team_id=<team-id>&limit=100" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sS -X PATCH "$BASE/roles/$ROLE_ID" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"senior-operator"}'
```

Bind the role to a user or group with [bindings](./bindings.md), then exercise the resulting decision through [permissions](./permissions.md). Platform roles use `{"team_id":null,"name":"platform-auditor"}`.

## Errors and links

Invalid JSON or no patch fields returns `400`; unknown roles return `404`; invalid or unregistered keys return `422`; scope violations return `403`. Deletion is audited and invalidates affected permission caches.
