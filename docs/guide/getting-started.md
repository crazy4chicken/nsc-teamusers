---
title: Getting started
outline: 2
---

# Getting started

`teamusers` is a standalone Go IAM service backed by PostgreSQL. The service
applies its embedded migrations on startup, keeps signing keys in a separate
protected directory, and serves the HTTP API on a local or leased listener.

## Prerequisites

- Go 1.24 or newer
- PostgreSQL 16 with an empty database and a role allowed to run migrations
- A protected directory for Ed25519 signing keys

## Build

Build the development binary from the repository root:

```sh
go build -o teamusers ./cmd/teamusers
```

For a Nekostick deployment, build the static Linux/amd64 artifact instead:

```sh
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
  go build -trimpath -ldflags '-s -w' -o teamusers ./cmd/teamusers
```

## Run locally

Set the connection string and a local listener before starting the service. The
key directory is created and populated with an Ed25519 signing key on the first
run when it is empty.

```sh
export TEAMUSERS_CONNECTION_STRING='postgres://<user>:<password>@127.0.0.1:5432/teamusers?sslmode=disable'
export TEAMUSERS_LISTEN_ADDRESS=127.0.0.1
export TEAMUSERS_LISTEN_PORT=8080
export TEAMUSERS_KEY_DIR="$PWD/data/keys"

go run ./cmd/teamusers run
```

Check liveness and database readiness from another terminal:

```sh
curl -fsS http://127.0.0.1:8080/healthz
curl -fsS http://127.0.0.1:8080/readyz
```

`healthz` is a process liveness check; `readyz` verifies that the service can
reach PostgreSQL. `teamusers status` prints redacted configuration, while
`teamusers doctor` checks the database, migration version, and key-directory
write access.

## Bootstrap the first administrator

A fresh deployment needs no database seeding. On startup, when no user holds
a platform administrative permission and no user named `admin` exists, the
service creates an `admin` user with a random temporary password and prints it
to the console:

```text
bootstrap: created the initial admin account
bootstrap:   username: admin
bootstrap:   temporary password: xk7Qp2…
bootstrap: the password must be changed on first login
```

The temporary credential is marked `must_change`: the first password login is
answered with `403 password_change_required` and a ten-minute
`password_change` token, so complete the change through `POST /me/password`
right after that first login attempt. The temporary password appears only in
the service's stdout; treat the deployment log as secret material until the
rotation is done.

To promote an existing user to platform administrator instead, or to recover
after the last administrative grant was removed, run the idempotent command:

```sh
export TEAMUSERS_CONNECTION_STRING='postgres://<user>:<password>@127.0.0.1:5432/teamusers?sslmode=disable'
./teamusers bootstrap-admin --username alice
```

The command ensures the nine enumerated platform `iam:<area>:any` permissions
and the `iam:*:any` wildcard, the platform-scoped `iam-admin` role, and a binding for
`alice`. The wildcard covers current and future IAM areas at the `:any` scope.
It is safe to run again; it never creates users, and the admin plane has no
unauthenticated HTTP bootstrap endpoint. On normal service startup, permission
reconciliation restores missing registrations and grants, so upgraded
deployments continue to work with the complete set.

Keep the database credentials and initial user's password under the same
out-of-band controls as other production secrets.

## First login

With the service running and the administrator's password provisioned, request
an access and refresh token from the public password-login endpoint:

```sh
export IAM_BASE_URL=http://127.0.0.1:8080

curl --fail-with-body -sS -X POST "$IAM_BASE_URL/auth/login" \
  -H 'Content-Type: application/json' \
  --data '{"username":"alice","password":"replace-with-the-provisioned-password"}'
```

A successful response contains a short-lived `access_token` and an opaque
`refresh_token`. Send the access token as `Authorization: Bearer <token>` for
admin and self-service requests. If TOTP is enabled, password login returns a
short-lived MFA challenge; complete it at `POST /auth/login/mfa` with a current
TOTP or one-time backup code before using the returned tokens.

If the account was provisioned with a temporary password (the automatic
bootstrap or an administrator-set password), login instead returns `403
password_change_required` with a `password_change` token; call
`POST /me/password` with that token as the bearer to set a new password before
continuing.

## Configuration summary

Configuration precedence is **CLI flag > environment variable > default**. The
most common environment variables are summarized below; see the
[operations runbook](/guide/operations#configuration-checklist) for the complete
table, production guidance, and secret-handling requirements.

| Variable | Default | Purpose |
| --- | --- | --- |
| `TEAMUSERS_CONNECTION_STRING` | empty | PostgreSQL DSN; required by `run` and `doctor`. |
| `TEAMUSERS_LISTEN_ADDRESS` | `127.0.0.1` | HTTP bind address; Nekostick can supply `HOST`. |
| `TEAMUSERS_LISTEN_PORT` | `0` | HTTP port; Nekostick can supply its leased `PORT`. |
| `TEAMUSERS_KEY_DIR` | `./data/keys` | Ed25519 private keys, public JWKs, and `ACTIVE`. |
| `TEAMUSERS_REGISTRATION_MODE` | `closed` | Public registration mode: `closed`, `approval`, or `open`. |
| `TEAMUSERS_WEBAUTHN_RP_ID` | `localhost` | WebAuthn relying-party ID. |
| `TEAMUSERS_WEBAUTHN_ORIGIN` | `http://localhost` | WebAuthn browser origin. |
