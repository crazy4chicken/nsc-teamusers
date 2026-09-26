# Audit API

## Use cases

Use the audit endpoint for compliance exports, incident response, and operational timelines. The service appends entries for administrative mutations, authentication events, session changes, and self-service security actions; there is no update or delete operation.

## Key concepts

- Each entry has an int64 `id`, optional team and actor ULIDs, an action, target, JSON `diff`, optional request ID, and RFC3339 `at` timestamp.
- `team_id` filters team-scoped entries. `cursor` is a non-negative integer ID, not an opaque ULID.
- `next_cursor: 0` means there is no next page; `limit` defaults to 100 and must be positive.
- Audit details intentionally avoid credential material and sensitive plaintext tokens.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET | `/audit?team_id=&cursor=0&limit=100` | Page append-only audit entries. |

The route requires `iam:audit:any` (or the allowed team-scoped audit grant). See [permissions](./permissions.md) for granting admin access.

## Page the audit log

```sh
BASE=http://localhost:8080
curl -sS "$BASE/audit?limit=100&cursor=0" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -sS "$BASE/audit?team_id=<team-id>&limit=25&cursor=0" \
  -H "Authorization: Bearer $ADMIN_TOKEN"
```

Continue with the numeric cursor returned by the previous response:

```sh
NEXT=123
curl -sS "$BASE/audit?limit=100&cursor=$NEXT" -H "Authorization: Bearer $ADMIN_TOKEN"
```

A typical entry looks like:

```json
{"id":1,"team_id":"01J8Z3TEAM000000000000001","actor_id":"01J8Z3ADMIN000000000000001","action":"user.created","target":"01J8Z3USER000000000000001","diff":{"status":"active"},"request_id":"req-01J8Z3","at":"2026-01-01T00:00:00Z"}
```

## Errors and links

A negative or non-numeric cursor returns `400` with `cursor must be a non-negative integer`; malformed limit returns `400`; missing/invalid bearer is `401`; insufficient grant is `403 insufficient_permissions`; storage failure is `500`. Review [users](./users.md), [sessions](./sessions.md), and [self-service](./self-service.md) to correlate lifecycle events.
