---
title: Subject targeting
outline: 2
---

# Subject targeting

A **subject** is a typed target identified by the pair
`(subject_kind, subject_id)`. The pair is the identity of the target; an ID by
itself is not enough because IDs from different resource kinds can otherwise be
ambiguous. This mechanism is intentionally generic so that cross-API features
can target the same users, teams, groups, and roles without defining a separate
selector model.

## Supported kinds

The service currently accepts these subject kinds:

| `subject_kind` | `subject_id` identifies |
| --- | --- |
| `user` | A user. |
| `team` | A team. |
| `group` | A group. |
| `role` | A role, including a platform-scoped role. |

The password-policy API verifies that the referenced resource exists when a
policy is created or its subject is changed. The subject pair remains the
reference even when the same resource is also reachable through a membership
or role binding.

For example, a rule record targeting every member of one team carries:

```json
{ "subject_kind": "team", "subject_id": "01JTEAM…" }
```

## Resolution for a user

A feature that resolves subjects for a user evaluates the current memberships
and role bindings at the resolution time:

- A `user` subject matches the user directly.
- A `team` subject matches when the user has an active membership in that team.
- A `group` subject matches when the user has an active membership in that
  group.
- A `role` subject matches when the user holds that role through an active
  unconditional role binding. Direct user bindings and group bindings inherited
  through the user's active memberships are considered. A team-scoped binding
  also requires the corresponding active team membership.

A membership or role binding is **active** when `expires_at` is `NULL` or in
the future relative to the resolution time. A role binding with a non-blank
`condition` (after trimming) is conditional and does **not** count as the user
holding that role for subject resolution. Conditions are request-time
authorization rules, so they are not used to decide a durable target for
password validation.

For example, a user who belongs to group `eng-core` in team `engineering` and
holds the platform role `iam-admin` matches rules targeting that user, the
`engineering` team, the `eng-core` group, and the `iam-admin` role at the
same time. How those matches combine is up to the consuming feature; password
policies merge them field by field through priority, as described in the
[security guide](/guide/security#password-policies).

Membership and binding changes therefore affect the next resolution; expired
memberships and bindings no longer make their subjects match. The resolver
uses the direct user and group binding paths and does not treat a conditional
binding as an unconditional role grant.

## Current API consumers

Password policies are the current consumer of generic subjects. The
administrative password-policy API uses subjects in:

- `GET /policies/password`
- `POST /policies/password`
- `GET /policies/password/{id}`
- `PATCH /policies/password/{id}`
- `DELETE /policies/password/{id}`

Those records are resolved for a target user whenever password requirements are
validated. The authenticated query endpoints `GET /me/password-policy` and
`GET /users/{id}/password-policy` expose the resulting merged policy for
frontend pre-validation; they do not return the individual subject rules.

Subject targeting is designed for reuse. Future cross-API features can use the
same `(subject_kind, subject_id)` model and membership/binding traversal rather
than adding another feature-specific target representation.

## Subject deletion and policies

Password-policy subject references are polymorphic, so the database cannot use
a single foreign key for all four kinds. The service validates a subject when a
policy is created or its subject is changed. When a targeted user, team, group,
or role is deleted through the administrative API, the service cascade-deletes
policies for that subject in the same transaction. Deleting a team also removes
policies targeting its groups and roles, which are deleted with the team. If a
subject disappears by any other path, its policies remain listable, editable,
and deletable.
