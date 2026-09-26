# Self-service API

## Use cases

Use `/me/*` from a signed-in web or mobile account page. Every request acts on the user in the bearer token; service subjects and attempts to address another user are rejected. This area covers profile edits, password/email changes, erasure/export, sessions, TOTP, and passkeys.

## Key concepts

- `GET/PATCH /me` exposes only profile fields; `PATCH` accepts only `display_name`.
- Password and email changes re-authenticate with the current password. Password changes revoke every refresh session.
- TOTP enrollment is two-step; backup codes are returned only at enrollment or regeneration. Passkey ceremonies use standard WebAuthn JSON and five-minute single-use challenges.
- Account export excludes credential hashes, service secrets, TOTP seeds, backup-code digests, and passkey public-key material.

## Endpoint table

| Method | Path | Purpose |
| --- | --- | --- |
| GET/PATCH | `/me` | Read/update display name. |
| POST | `/me/password` | Change password and revoke sessions. |
| POST | `/me/email` | Request email replacement. |
| POST | `/me/email/confirm` | Consume replacement token. |
| DELETE | `/me` | Erase/anonymize account. |
| GET | `/me/export` | Download account data. |
| GET/DELETE | `/me/sessions[/{id}]` | Manage own sessions. |
| POST/DELETE | `/me/totp`, `/me/totp/*` | Enroll, confirm, regenerate, disable MFA. |
| GET/DELETE | `/me/passkeys[/{credID}]` | List/delete passkeys. |
| POST | `/me/passkeys/register/begin` | Start WebAuthn registration. |
| POST | `/me/passkeys/register/finish` | Finish WebAuthn registration. |

## Profile, password, and export

```sh
BASE=http://localhost:8080
curl -sS "$BASE/me" -H "Authorization: Bearer $ACCESS_TOKEN"
curl -sS -X PATCH "$BASE/me" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"display_name":"Alice Smith"}'
curl -sS "$BASE/me/export" -H "Authorization: Bearer $ACCESS_TOKEN" -o user-export.json
```

Rotate a password, then sign in again because all sessions are revoked:

```sh
curl -sS -X POST "$BASE/me/password" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"current_password":"OldAtLeastTwelve1","new_password":"NewAtLeastTwelve2"}'
```

## Email and TOTP

```sh
curl -i -X POST "$BASE/me/email" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"new_email":"alice.new@example.test","password":"CurrentAtLeastTwelve1"}'
curl -i -X POST "$BASE/me/email/confirm" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"token":"<email-change-token>"}'
TOTP=$(curl -sS -X POST "$BASE/me/totp/enroll" -H "Authorization: Bearer $ACCESS_TOKEN")
printf '%s\n' "$TOTP"
curl -sS -X POST "$BASE/me/totp/confirm" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'
```

Regenerate backup codes with the current password or disable MFA using a current TOTP/backup code:

```sh
curl -sS -X POST "$BASE/me/totp/backup-codes" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"password":"CurrentAtLeastTwelve1"}'
curl -i -X DELETE "$BASE/me/totp" -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H 'Content-Type: application/json' -d '{"code":"123456"}'
```

## Errors and links

Expect `401 authentication failed` or `invalid_credentials`, `400 invalid_token`, `409 totp_already_enabled`, `404 mfa_not_enrolled`, `422 weak_password`, `429 authentication temporarily busy`, and WebAuthn `400 invalid WebAuthn response`. See [sessions](./sessions.md), [authentication](./authentication.md), [permissions](./permissions.md), and the [permissions guide](../guide/permissions.md).
