# Permissions API

## Use cases

Use the permission registry when an application service introduces a new capability, and use the service authorization endpoints when that service needs a decision at request time. Registry administration requires `iam:permissions:any`; evaluation requires a service bearer.

## Key concepts

- A key has `resource:action:scope` grammar, where scope is commonly `any`, `team`, or `own`.
- Registration is an upsert and bumps the global permission registry version.
- Roles contain keys; bindings connect roles to users or groups. Conditions are evaluated fail-closed.
- `perm_ver` is the user grant version. Cache effective grants only while the version matches.

## Endpoint table

| Method | Path | Caller | Purpose |
| --- | --- | --- | --- |
| GET | `/permissions?cursor=&limit=` | Admin | List registered keys. |
| POST | `/permissions` | Admin | Register/upsert a key. |
| POST | `/authz/check` | Service | Evaluate one resource decision. |
| GET | `/authz/permissions/{userID}` | Service | Fetch effective grants and `perm_ver`. |

## Register a key and build a role

```sh
BASE=http://localhost:8080
curl -sS -X POST "$BASE/permissions" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"key":"orders:read:team","description":"Read orders in a team","registered_by":"orders-service"}'
curl -sS "$BASE/permissions?limit=100" -H "Authorization: Bearer $ADMIN_TOKEN"
ROLE=$(curl -sS -X POST "$BASE/roles" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"team_id":"<team-id>","name":"order-reader"}')
ROLE_ID=$(printf '%s' "$ROLE" | jq -r .id)
curl -sS -X PUT "$BASE/roles/$ROLE_ID/permissions" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"permission_keys":["orders:read:team"]}'
```

After binding the role (see [bindings](./bindings.md)), a service fetches effective grants and checks a resource:

```sh
curl -sS "$BASE/authz/permissions/<user-id>" -H "Authorization: Bearer $SERVICE_TOKEN"
curl -sS -X POST "$BASE/authz/check" -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H 'Content-Type: application/json' -d '{"subject":"<user-id>","permission":"orders:read:team","context":{"resource":{"owner_id":"<owner-id>","team_id":"<team-id>","attrs":{"region":"us-east-1"}}}}'
```

A decision has `allow`, `matched`, and `reason` (`permission granted`, `no matching grant`, `condition denied`, `permission denied`, or `user disabled`). The resolver is fail-closed when a condition cannot be evaluated.

## Errors and links

Malformed input is `400`; invalid permission grammar is `422`; a missing user is `404`; an invalid service subject is `401`; resolver failure is `500`. Administrative grant setup is covered by [roles](./roles.md), [groups](./groups.md), and [bindings](./bindings.md).
