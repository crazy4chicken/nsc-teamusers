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
memberships and bindings no longer make their subjects match. Password-policy
subject resolution continues to use direct user and group binding paths and does
not treat conditional bindings as unconditional role grants. Authorization
baseline traversal is separate and does not add team baselines to password-,
session-, or MFA-policy role-target resolution.



## Authorization binding traversal

`POST /bindings` also accepts `subject_kind=team` for one authorization baseline
per team. `subject_id` is the team ID; `team_id` may be omitted and inferred, or
must equal `subject_id` when supplied. The role may be platform-scoped or owned
by that same team; foreign-team roles are rejected. A baseline may carry a
condition and allow or deny permissions but cannot expire. It is one team
binding, not a set of per-user copies or a default group.

Authorization resolves a user's grants through three binding paths:

- A direct user binding targets that user.
- A group binding targets a group in which the user has an unexpired membership.
- A team baseline is inherited when the user has at least one unexpired
  membership in any group in that active team. Memberships across the team's
  groups form a union: one valid membership is sufficient, and removing or
  expiring the last valid membership removes baseline eligibility.

Every team-scoped binding grant is limited to a request whose `resource.team_id`
matches the binding's team, and scoped grants are suppressed while that team is
disabled. A permission key ending in `:any` does not remove this binding-team
filter. Platform bindings with `team_id: null` remain independent of team
membership and are not affected by a baseline deny unless the platform user is
also an eligible member of that team and the deny matches the resource.

## Current policy subject consumers

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

Authorization bindings now use the same `(subject_kind, subject_id)` model for
team baselines, while password-, session-, and MFA-policy role targeting keeps
its existing resolution paths. Other features can reuse this model without
changing those policy semantics.

## Subject deletion and policies

Password-policy subject references are polymorphic, so the database cannot use
a single foreign key for all four kinds. The service validates a subject when a
policy is created or its subject is changed. When a targeted user, team, group,
or role is deleted through the administrative API, the service cascade-deletes
policies for that subject in the same transaction. Deleting a team also removes
policies targeting its groups and roles, which are deleted with the team. If a
subject disappears by any other path, its policies remain listable, editable,
and deletable.
