# Groups API

## Use cases

Use groups to collect users inside a team and to assign group-based roles. The group API supports individual membership changes and independent per-row batch additions for onboarding or migration workflows.

## Key concepts

- A group has exactly one `team_id`; a membership stores `team_id`, `group_id`, `user_id`, and optional `expires_at`.
- Membership changes bump each affected user's `perm_ver` and therefore invalidate stale access tokens.
- `PUT /groups/{id}/members` is idempotent; batch addition reports duplicate rows as `already_member`.
- Group collection reads require `team_id`; all group operations need `iam:groups:any` or a team-scoped grant.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/groups?team_id=&cursor=&limit=` | List groups in a team. |
| POST | `/groups` | Create a group. |
| GET | `/groups/{id}` | Read a group. |
| PATCH | `/groups/{id}` | Rename or move a group. |
| DELETE | `/groups/{id}` | Delete a group and memberships. |
| PUT | `/groups/{id}/members` | Add/update one membership. |
| DELETE | `/groups/{id}/members` | Remove one membership using JSON user_id. |
| DELETE | `/groups/{id}/members/{userID}` | Remove one membership by path. |
| POST | `/groups/{id}/members/batch` | Add up to 500 users independently. |

## Create a group and membership

```sh
BASE=http://localhost:8080
GROUP=$(curl -sS -X POST "$BASE/groups" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"team_id":"<team-id>","name":"backend"}')
GROUP_ID=$(printf '%s' "$GROUP" | jq -r .id)
curl -sS "$BASE/groups?team_id=<team-id>&limit=100" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sS -X PUT "$BASE/groups/$GROUP_ID/members" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"user_id":"<user-id>","expires_at":"2026-02-01T00:00:00Z"}'
```

Bulk add users and then remove a member:

```sh
curl -sS -X POST "$BASE/groups/$GROUP_ID/members/batch" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"user_ids":["<user-id>","<other-user-id>"]}'
curl -i -X DELETE "$BASE/groups/$GROUP_ID/members/<user-id>" -H "Authorization: Bearer $ADMIN_TOKEN"
```

The resulting group can receive a role binding; continue with [roles](./roles.md) and [bindings](./bindings.md). The permission version behavior is explained in the [API permissions](./permissions.md) page and [permissions guide](../guide/permissions.md).

## Errors and links

`team_id` missing on list is `400`; unknown users, groups, or memberships are `404`; over 500 batch IDs are `422`; duplicate rows are returned as `already_member` in a successful batch response. Administrative authentication and scope failures are `401` or `403 insufficient_permissions`. See the [permissions guide](../guide/permissions.md) for scope rules.
