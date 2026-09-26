# Bindings API

## Use cases

Use role bindings to assign a role to a user or group, optionally within a team, under a condition, or until an expiry. This is the final link between [roles](./roles.md) and the users evaluated by [permissions](./permissions.md) and the [permissions guide](../guide/permissions.md).

## Key concepts

- `subject_kind` is `user` or `group`; `subject_id` is the corresponding ULID.
- `team_id` is optional when it can be inferred from the role or group. Explicit mismatches are rejected.
- Conditions are compiled at creation and evaluated against the authorization request; failures deny access.
- Binding changes invalidate affected users' `perm_ver` and are audited. Admin calls require `iam:bindings:any`.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/bindings?subject_kind=&subject_id=&cursor=&limit=` | List bindings for a subject. |
| POST | `/bindings` | Create a user/group role binding. |
| DELETE | `/bindings/{id}` | Delete a binding. |

## Bind a role to a user and check it

```sh
BASE=http://localhost:8080
BINDING=$(curl -sS -X POST "$BASE/bindings" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"team_id":"<team-id>","role_id":"<role-id>","subject_kind":"user","subject_id":"<user-id>","condition":"resource.team_id == subject.team_id"}')
BINDING_ID=$(printf '%s' "$BINDING" | jq -r .id)
curl -sS "$BASE/bindings?subject_kind=user&subject_id=<user-id>&limit=100" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sS -X POST "$BASE/authz/check" -H "Authorization: Bearer $SERVICE_TOKEN" \
  -H 'Content-Type: application/json' -d '{"subject":"<user-id>","permission":"orders:read:team","context":{"resource":{"owner_id":"<owner-id>","team_id":"<team-id>","attrs":{}}}}'
```

Bind to a group with an expiry, then remove the assignment:

```sh
curl -sS -X POST "$BASE/bindings" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"role_id":"<role-id>","subject_kind":"group","subject_id":"<group-id>","expires_at":"2026-02-01T00:00:00Z"}'
curl -i -X DELETE "$BASE/bindings/$BINDING_ID" -H "Authorization: Bearer $ADMIN_TOKEN"
```

## Errors and links

Missing role/subject references are `404`; malformed fields and team mismatches are `400`; invalid conditions are `422`; duplicate database bindings may return `409`; insufficient admin grants return `403 insufficient_permissions`. Pair this page with [groups](./groups.md), [roles](./roles.md), [permissions](./permissions.md), and the [permissions guide](../guide/permissions.md).
