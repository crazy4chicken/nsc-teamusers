# Teams API

## Use cases

Use teams to model tenants, workspaces, or organizational boundaries. Administrators create and maintain team records before creating team-scoped groups, roles, and bindings. Every operation requires the admin permission `iam:teams:any` or a matching team-scoped grant.

## Key concepts

- Team IDs are ULIDs; `slug` is the external stable name and `name` is display text.
- `status` is `active` or `disabled`. Team deletion invalidates affected users' permission versions.
- Collection responses use `items` and an opaque `next_cursor`; use `limit` only as a positive integer.
- A team ID is carried by group membership, team roles, role bindings, and authorization resource context.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/teams?cursor=&limit=` | List teams. |
| POST | `/teams` | Create a team. |
| GET | `/teams/{id}` | Read a team. |
| PATCH | `/teams/{id}` | Rename/change slug or status. |
| DELETE | `/teams/{id}` | Delete a team and dependent records. |

## Create a team and inspect it

```sh
BASE=http://localhost:8080
TEAM=$(curl -sS -X POST "$BASE/teams" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"slug":"acme","name":"Acme","status":"active"}')
TEAM_ID=$(printf '%s' "$TEAM" | jq -r .id)
curl -sS "$BASE/teams/$TEAM_ID" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sS "$BASE/teams?limit=100" -H "Authorization: Bearer $ADMIN_TOKEN"
```

Update metadata, then disable it if access should be suspended:

```sh
curl -sS -X PATCH "$BASE/teams/$TEAM_ID" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"name":"Acme Europe"}'
curl -sS -X PATCH "$BASE/teams/$TEAM_ID" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"status":"disabled"}'
```

A team is the starting point for the policy flow in [groups](./groups.md), [roles](./roles.md), and [bindings](./bindings.md). See [permissions](./permissions.md) for how `iam:teams:any` is granted.

## Errors and links

Malformed JSON or an empty required field returns `400`; duplicates map to `409`; unknown IDs map to `404`; invalid status maps to `422`; missing admin grants map to `403 insufficient_permissions`. Team deletion is irreversible and should be audited through [audit](./audit.md).
