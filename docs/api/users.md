# Users API

## Use cases

Use the users API for administrator-driven provisioning, profile maintenance, status changes, imports, credential rotation, and approval. It requires a user access token with `iam:users:any` (or an allowed team-scoped grant for the applicable target). Service subjects cannot call it.

## Key concepts

- User IDs are ULIDs. `status` is `pending`, `invited`, `active`, or `disabled`.
- `perm_ver` invalidates previously issued access tokens when status or permissions change.
- `password` and `initial_password` are accepted on creation; `password` wins. Password material is never returned.
- Disable operations revoke sessions, reset lockout state, and invalidate permissions. Batch operations report each row independently.
- CSV import requires the exact header `username,email,display_name,password` and at most 500 rows.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/users?cursor=&limit=` | Cursor-page users. |
| POST | `/users` | Create an active user. |
| POST | `/users/batch` | Enable/disable up to 500 users. |
| POST | `/users/import` | Import active users from CSV. |
| GET | `/users/{id}` | Read one user. |
| PATCH | `/users/{id}` | Change profile fields or status. |
| DELETE | `/users/{id}` | Hard-delete a user. |
| POST | `/users/{id}/disable` | Dedicated disable transition. |
| POST | `/users/{id}/approve` | Approve a verified pending user. |
| POST | `/users/{id}/credentials` | Create/rotate password or service credential. |
| DELETE | `/users/{id}/totp` | Administrative MFA reset. |

## Create and inspect a user

```sh
BASE=http://localhost:8080
curl -sS -X POST "$BASE/users" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.test","display_name":"Alice Example","password":"AtLeastTwelve1"}'
curl -sS "$BASE/users?limit=25" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sS "$BASE/users/<user-id>" -H "Authorization: Bearer $ADMIN_TOKEN"
```

Update a profile or disable an account:

```sh
curl -sS -X PATCH "$BASE/users/<user-id>" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"display_name":"Alice Smith"}'
curl -sS -X POST "$BASE/users/<user-id>/disable" -H "Authorization: Bearer $ADMIN_TOKEN"
```

Batch status changes return `{results:[...]}` with `not_found`, `invalid_id`, or `operation_failed` per row:

```sh
curl -sS -X POST "$BASE/users/batch" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' -d '{"ids":["<user-id>","<missing-id>"],"op":"disable"}'
```

Import a CSV (use `--data-binary` so commas and newlines are preserved):

```sh
curl -sS -X POST "$BASE/users/import" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: text/csv' --data-binary $'username,email,display_name,password\nalice,alice@example.test,Alice Example,AtLeastTwelve1\n'
```

## Errors and links

Common failures are `401` authentication failed, `403` insufficient_permissions, `404` not found, `409` resource already exists, `422` weak_password or validation detail, and `500` database failure. Session operations are documented in [sessions](./sessions.md), invitations in [invitations](./invitations.md), and the required role grants in [permissions](./permissions.md).
