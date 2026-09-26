# Invitations API

## Use cases

Use invitations when an administrator wants to provision an account without open self-registration. The admin creates an invited user, notification delivery sends a one-time token, and the recipient accepts it to set a password and become active.

## Key concepts

- Administrative invitation routes require `iam:users:any`; the public accept route does not require a bearer.
- Invitation tokens are single-use and expire after seven days. Plaintext tokens appear only in notification outbox events.
- An invited user remains `status: invited` until acceptance. Resend invalidates the previous token. Cancellation deletes the invited account.
- Acceptance marks the invitation email verified and optionally sets display_name.

## Endpoint table

| Method | Path | Caller | Purpose |
| --- | --- | --- | --- |
| POST | `/invitations` | Admin | Create an invited user and notification. |
| POST | `/invitations/{userID}/resend` | Admin | Rotate and resend a token. |
| DELETE | `/invitations/{userID}` | Admin | Cancel/delete an invitation. |
| POST | `/auth/invite/accept` | Public recipient | Set password and activate account. |

## Create and accept an invitation

```sh
BASE=http://localhost:8080
INVITED=$(curl -sS -X POST "$BASE/invitations" -H "Authorization: Bearer $ADMIN_TOKEN" \
  -H 'Content-Type: application/json' \
  -d '{"email":"alice@example.test","username":"alice","display_name":"Alice Example"}')
USER_ID=$(printf '%s' "$INVITED" | jq -r .id)
# The notification service supplies <invitation-token> to the recipient.
curl -i -X POST "$BASE/auth/invite/accept" -H 'Content-Type: application/json' \
  -d '{"token":"<invitation-token>","password":"AtLeastTwelve1","display_name":"Alice Example"}'
curl -sS -X POST "$BASE/auth/login" -H 'Content-Type: application/json' \
  -d '{"username":"alice","password":"AtLeastTwelve1"}'
```

Resend when delivery failed, or cancel before acceptance:

```sh
curl -i -X POST "$BASE/invitations/$USER_ID/resend" -H "Authorization: Bearer $ADMIN_TOKEN"
curl -i -X DELETE "$BASE/invitations/$USER_ID" -H "Authorization: Bearer $ADMIN_TOKEN"
```

The invitation flow is an alternative to [authentication](./authentication.md) self-registration and commonly follows team/user setup in [users](./users.md). Granting the admin ability is described in [permissions](./permissions.md).

## Errors and links

Public acceptance returns `400 invalid_token` for missing, expired, used, wrong-kind, cancelled, or active-account tokens and `422 weak_password` for policy failure. Admin creation validates email/username (`400`), duplicates (`422`), and authentication/scope (`401`/`403`). Resend and cancellation return `404` for unknown users and `422 account is not invited` for non-invited users.
