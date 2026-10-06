---
title: REST collection pagination
outline: 2
---

# REST collection pagination

REST collection lists use string keyset cursors. A cursor identifies the last
ordering key returned by a page; it is not an offset and does not change the
route's authorization or resource scope. Keep the same route filters and bearer
identity while walking a result set.

## Request and response contract

All paged REST collection routes accept optional `cursor` and `limit` query
parameters. Cursor input is trimmed for surrounding whitespace. Thus, for
routes other than passkeys, a whitespace-only cursor behaves as empty and
requests the first page; passkey routes reject surrounding whitespace instead.
Omit `cursor` or send an empty string for the first page, then pass each
returned cursor back unchanged. Audit and login-activity routes also accept
`cursor=0` as their first page.

`limit` defaults to 100. A supplied limit must be a positive integer; values
above 1000 are capped at an effective page size of 1000. Invalid or non-positive
limits return HTTP 400.

Every page has this shape:

```json
{
  "items": [],
  "next_cursor": ""
}
```

`next_cursor` is always a JSON string. An empty string means the returned page
is shorter than the effective limit and is terminal. The implementation does
not look ahead: a full page returns its last ordering key even when it contains
the final rows. If the final page is exactly full, request the returned cursor
once more; that follow-up returns an empty `items` array and `next_cursor: ""`.

Cursors are keys, not page numbers. Use one only with the same collection and
filter that produced it. The current bearer, path user, team, subject, active
session, and other endpoint filters continue to determine scope.

## Collection ordering and scope

| Collection | Keyset order and route scope |
| --- | --- |
| `GET /users/` | User ID ascending. |
| `GET /teams/` | Team ID ascending. |
| `GET /groups/` | Group ID ascending within the required `team_id`. |
| `GET /policies/password` | Password-policy ID ascending. |
| `GET /policies/mfa` | MFA-policy ID ascending. |
| `GET /roles/` | Role ID ascending; optional `team_id` filter. |
| `GET /roles/{id}/permissions` | Permission key ascending within the path role. |
| `GET /permissions/` | Permission key ascending. |
| `GET /bindings/` | Binding ID ascending for the required `subject_kind` and `subject_id`. |
| `GET /audit` | Numeric audit ID ascending; optional `team_id` filter. Rows remain append-only while retained. |
| `GET /users/{id}/sessions` | Active, unexpired sessions for the path user, ordered by `created_at` ascending then session ID ascending. |
| `GET /me/sessions` | Active, unexpired sessions for the bearer user, ordered by `created_at` ascending then session ID ascending. |
| `GET /me/activity` | Numeric activity ID descending, restricted to the bearer user's rows. Rows with no resolved user are not visible here. |
| `GET /me/passkeys` | Credential IDs ascending by their exposed, unpadded base64url string, restricted to the bearer user. |

Audit and activity item `id` fields remain JSON numbers. After shared
whitespace trimming, `cursor` values are parsed as base-10 `int64`s. A leading
`+` and leading zeros are accepted, but the value must be non-negative. `0`
starts from the beginning; malformed, negative, or overflowing values return
HTTP 400. `next_cursor` is the last audit/activity ID as a canonical base-10
decimal string, with no leading `+` or unnecessary zeros.

Session cursors encode the complete `(created_at, id)` ordering key as an
opaque `base64.RawURLEncoding` cursor. This includes the session ID tie-breaker
for rows with identical creation timestamps. Surrounding whitespace is trimmed
before decoding and is tolerated. Malformed encodings, a missing field separator,
invalid timestamps, or empty/NUL-containing session IDs return HTTP 400. Do not
construct or parse session cursors; pass the returned value unchanged.

Passkey IDs are canonical `base64.RawURLEncoding` values of credential IDs and
are also the cursor keys. Results are ordered lexicographically by that exposed
string; the next page contains IDs strictly greater than the cursor. A passkey
cursor must be a canonical, non-empty unpadded base64url credential ID with no
surrounding whitespace; otherwise the request returns HTTP 400. The item schema
remains `id` and `created_at`; public keys and attestation data are not returned.

## Protocol and full-response exceptions

This guide covers REST collection lists only. SCIM endpoints retain their
SCIM-specific `startIndex`/`count` pagination and SCIM response envelope; see the
[SCIM API reference](../api/reference/scim) and [operations runbook](./operations.md)
for that protocol's behavior.

The flat, display-only permission response `GET /me/permissions` and the
versioned permission snapshot `GET /authz/permissions/{userID}?version=2` are
not converted into cursor pages. They retain their existing response shapes.

The full account export `GET /me/export` and complete audit export
`GET /audit/export` are not paginated; they retain their existing response
shapes and completeness semantics.

The JWKS signing-key set `GET /.well-known/jwks.json` and the fixed SCIM
capability and resource-type responses `GET /scim/v2/ServiceProviderConfig`
and `GET /scim/v2/ResourceTypes` are protocol responses, not resource pages.

## Client migration

`GET /audit` and `GET /me/activity` previously returned numeric
`next_cursor` values (`0` when terminal); they now return the decimal cursor as
a string and use `""` for a terminal page. Their item IDs remain numeric.

`GET /users/{id}/sessions`, `GET /me/sessions`, and `GET /me/passkeys` previously
returned bare arrays; they now return the common
`{ "items": [...], "next_cursor": "..." }` envelope. Session and passkey item
fields are unchanged. Update clients to read collection items from `items`,
treat `next_cursor` as a string, and stop only when it is empty.
