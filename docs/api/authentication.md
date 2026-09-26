# Authentication API

## Use cases

Use this page for public account creation, sign-in, service credentials, recovery, invitation acceptance, passkey login, and access-token lifecycle. Browser and mobile clients normally use password or passkey login; backend services use client credentials. Notification delivery is out-of-band: verification, reset, and invitation tokens are never returned by the HTTP response.

## Key concepts

- Access tokens are ten-minute EdDSA JWTs. Refresh tokens are opaque and rotate on every refresh.
- Registration creates `pending` users in `open` or `approval` mode. Email verification activates an open account; approval mode additionally requires an admin approval.
- A confirmed TOTP enrollment makes password login return `{mfa_required:true,mfa_token}`. Complete it with a TOTP or one-time backup code.
- Password, reset, invitation, and verification tokens are single-use. Invalid tokens return `invalid_token` without revealing account state.
- `/.well-known/jwks.json` is public and contains only public signing keys.

## Endpoint table

| Method | Path | Caller | Purpose |
| --- | --- | --- | --- |
| GET | `/.well-known/jwks.json` | Public | Fetch Ed25519 verification keys. |
| POST | `/auth/register` | Public | Create a pending self-registration. |
| POST | `/auth/verify-email` | Public | Consume an email verification token. |
| POST | `/auth/login` | Public | Password login or MFA challenge. |
| POST | `/auth/login/mfa` | Public | Complete a TOTP/backup-code challenge. |
| POST | `/auth/passkey/login/begin` | Public | Begin WebAuthn assertion. |
| POST | `/auth/passkey/login/finish` | Public | Finish WebAuthn assertion and issue tokens. |
| POST | `/auth/client-credentials` | Public | Exchange service ID/secret for service tokens. |
| POST | `/auth/refresh` | Public | Rotate a refresh token. |
| POST | `/auth/logout` | Public | Revoke a refresh-token family idempotently. |
| POST | `/auth/introspect` | Service bearer | Inspect an access or refresh token. |
| POST | `/auth/password-reset/request` | Public | Start account recovery without enumeration. |
| POST | `/auth/password-reset/confirm` | Public | Set a password with a reset token. |
| POST | `/auth/invite/accept` | Public | Activate an invited account. |

## Password flow

Register, verify through the notification token, log in, and refresh the pair:

```sh
BASE=http://localhost:8080
curl -sS -X POST "$BASE/auth/register" -H 'Content-Type: application/json' \
  -d '{"username":"alice","email":"alice@example.test","password":"AtLeastTwelve1","display_name":"Alice Example"}'
# Notification service delivers the verification token.
curl -i -X POST "$BASE/auth/verify-email" -H 'Content-Type: application/json' \
  -d '{"token":"<verification-token>"}'
TOKENS=$(curl -sS -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"AtLeastTwelve1"}')
printf '%s\n' "$TOKENS"
curl -sS -X POST "$BASE/auth/refresh" -H 'Content-Type: application/json' \
  -d "$(printf '%s' "$TOKENS" | jq -c '{refresh_token}')"
```

When login returns MFA, submit the challenge:

```sh
curl -sS -X POST "$BASE/auth/login/mfa" -H 'Content-Type: application/json' \
  -d '{"mfa_token":"<mfa-token>","code":"123456"}'
```

Use a service credential for backend calls. An administrator first creates the credential; the generated secret must be stored immediately:

```sh
curl -sS -X POST "$BASE/users/<service-user-id>/credentials" \
  -H "Authorization: Bearer $ADMIN_TOKEN" -H 'Content-Type: application/json' \
  -d '{"kind":"service"}'
SERVICE=$(curl -sS -X POST "$BASE/auth/client-credentials" -H 'Content-Type: application/json' \
  -d '{"client_id":"orders-service","client_secret":"<generated-secret>"}')
```

Password recovery is intentionally non-observable:

```sh
curl -i -X POST "$BASE/auth/password-reset/request" -H 'Content-Type: application/json' \
  -d '{"login":"alice@example.test"}'
# Deliver the token from notifications, then:
curl -i -X POST "$BASE/auth/password-reset/confirm" -H 'Content-Type: application/json' \
  -d '{"token":"<reset-token>","new_password":"NewAtLeastTwelve1"}'
```

## Errors and links

Expect `401` `authentication failed`, `403` `account_pending`, `423` `account_locked`, `429` `authentication temporarily busy`, `400` `invalid_token`, and `422` `weak_password` where applicable. See [self-service](./self-service.md) for TOTP/passkey enrollment, [invitations](./invitations.md) for the admin invitation lifecycle, and the [permissions guide](../guide/permissions.md) for service authorization.
