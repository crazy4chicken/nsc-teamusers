# Sessions API

## Use cases

Use session endpoints for account-security UIs, device sign-out, incident response, and administrative revocation after a credential change. Refresh sessions are opaque and never expose refresh tokens or client metadata.

## Key concepts

- A session response contains only digest `id`, `created_at`, and `expires_at`.
- User self-service can list and revoke its own sessions. Administrators can list or revoke another user's sessions with `iam:sessions:any`.
- Password changes, password-reset confirmation, and disabling a user revoke sessions as part of the security transition.
- `DELETE` is idempotent only for known ownership: unknown or foreign IDs return `404`.

## Endpoint table

| Method | Path | Caller | Purpose |
| --- | --- | --- | --- |
| GET | `/me/sessions` | User bearer | List own active sessions. |
| DELETE | `/me/sessions/{id}` | User bearer | Revoke one own session. |
| GET | `/users/{id}/sessions` | Admin | List target user's sessions. |
| DELETE | `/users/{id}/sessions/{sid}` | Admin | Revoke one target session. |
| DELETE | `/users/{id}/sessions` | Admin | Revoke all target sessions. |

## User self-service flow

```sh
BASE=http://localhost:8080
curl -sS "$BASE/me/sessions" -H "Authorization: Bearer $ACCESS_TOKEN"
curl -i -X DELETE "$BASE/me/sessions/<session-digest>" -H "Authorization: Bearer $ACCESS_TOKEN"
```

## Administrative incident response

```sh
curl -sS "$BASE/users/<user-id>/sessions" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -i -X DELETE "$BASE/users/<user-id>/sessions/<session-digest>" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
curl -i -X DELETE "$BASE/users/<user-id>/sessions" -H "Authorization: Bearer $ADMIN_TOKEN"
```

Use [authentication](./authentication.md) for refresh rotation and [users](./users.md) for account status transitions. See [security](../guide/security.md) for token revocation semantics.

## Errors and links

A missing or stale access token is `401`; an admin lacking `iam:sessions:any` is `403 insufficient_permissions`; unknown users or session IDs are `404`; storage errors are `500`. The response intentionally does not reveal whether a session belongs to another account.
