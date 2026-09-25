package store

import (
	"context"

	"github.com/jackc/pgx/v5"
)

func CreateTeam(ctx context.Context, q Q, team Team) (Team, error) {
	if team.ID == "" {
		team.ID = NewID()
	}
	return scanTeam(q.QueryRow(ctx, `
		INSERT INTO teams (id, slug, name, status)
		VALUES ($1, $2, $3, $4)
		RETURNING id, slug, name, status, created_at`,
		team.ID, team.Slug, team.Name, team.Status))
}

func GetTeam(ctx context.Context, q Q, id string) (Team, error) {
	return scanTeam(q.QueryRow(ctx, `
		SELECT id, slug, name, status, created_at FROM teams WHERE id = $1`, id))
}

func ListTeams(ctx context.Context, q Q, cursor string, limit int) ([]Team, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT id, slug, name, status, created_at FROM teams
			ORDER BY id LIMIT $1`, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, slug, name, status, created_at FROM teams
			WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	teams := make([]Team, 0, limit)
	for rows.Next() {
		team, err := scanTeam(rows)
		if err != nil {
			return nil, "", err
		}
		teams = append(teams, team)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return teams, nextCursor(len(teams), limit, func(i int) string { return teams[i].ID }), nil
}

func UpdateTeam(ctx context.Context, q Q, team Team) (Team, error) {
	return scanTeam(q.QueryRow(ctx, `
		UPDATE teams SET slug = $2, name = $3, status = $4
		WHERE id = $1
		RETURNING id, slug, name, status, created_at`,
		team.ID, team.Slug, team.Name, team.Status))
}

func DeleteTeam(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM teams WHERE id = $1`, id)
	return err
}

func CreateGroup(ctx context.Context, q Q, group Group) (Group, error) {
	if group.ID == "" {
		group.ID = NewID()
	}
	return scanGroup(q.QueryRow(ctx, `
		INSERT INTO groups (id, team_id, name)
		VALUES ($1, $2, $3)
		RETURNING id, team_id, name`, group.ID, group.TeamID, group.Name))
}

func GetGroup(ctx context.Context, q Q, id string) (Group, error) {
	return scanGroup(q.QueryRow(ctx, `
		SELECT id, team_id, name FROM groups WHERE id = $1`, id))
}

func ListGroups(ctx context.Context, q Q, teamID, cursor string, limit int) ([]Group, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT id, team_id, name FROM groups
			WHERE team_id = $1 ORDER BY id LIMIT $2`, teamID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, team_id, name FROM groups
			WHERE team_id = $1 AND id > $2 ORDER BY id LIMIT $3`, teamID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	groups := make([]Group, 0, limit)
	for rows.Next() {
		group, err := scanGroup(rows)
		if err != nil {
			return nil, "", err
		}
		groups = append(groups, group)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return groups, nextCursor(len(groups), limit, func(i int) string { return groups[i].ID }), nil
}

func UpdateGroup(ctx context.Context, q Q, group Group) (Group, error) {
	return scanGroup(q.QueryRow(ctx, `
		UPDATE groups SET team_id = $2, name = $3
		WHERE id = $1 RETURNING id, team_id, name`, group.ID, group.TeamID, group.Name))
}

func DeleteGroup(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM groups WHERE id = $1`, id)
	return err
}

// PutMembership inserts or replaces one group membership.
func PutMembership(ctx context.Context, q Q, membership Membership) error {
	_, err := q.Exec(ctx, `
		INSERT INTO memberships (team_id, group_id, user_id, expires_at)
		VALUES ($1, $2, $3, $4)
		ON CONFLICT (group_id, user_id)
		DO UPDATE SET team_id = EXCLUDED.team_id, expires_at = EXCLUDED.expires_at`,
		membership.TeamID, membership.GroupID, membership.UserID, membership.ExpiresAt)
	return err
}

func DeleteMembership(ctx context.Context, q Q, groupID, userID string) error {
	_, err := q.Exec(ctx, `
		DELETE FROM memberships WHERE group_id = $1 AND user_id = $2`, groupID, userID)
	return err
}

// ListAllMembershipsByUser returns every membership row for an export. Unlike
// the administrative listing helper, this has no page limit.
func ListAllMembershipsByUser(ctx context.Context, q Q, userID string) ([]Membership, error) {
	rows, err := q.Query(ctx, `
		SELECT team_id, group_id, user_id, expires_at
		FROM memberships WHERE user_id = $1 ORDER BY group_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	memberships := make([]Membership, 0)
	for rows.Next() {
		membership, err := scanMembership(rows)
		if err != nil {
			return nil, err
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return memberships, nil
}

func ListMembershipsByUser(ctx context.Context, q Q, userID, cursor string, limit int) ([]Membership, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT team_id, group_id, user_id, expires_at FROM memberships
			WHERE user_id = $1 ORDER BY group_id LIMIT $2`, userID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT team_id, group_id, user_id, expires_at FROM memberships
			WHERE user_id = $1 AND group_id > $2 ORDER BY group_id LIMIT $3`, userID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	memberships := make([]Membership, 0, limit)
	for rows.Next() {
		membership, err := scanMembership(rows)
		if err != nil {
			return nil, "", err
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return memberships, nextCursor(len(memberships), limit, func(i int) string { return memberships[i].GroupID }), nil
}

func ListMembershipsByGroup(ctx context.Context, q Q, groupID, cursor string, limit int) ([]Membership, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT team_id, group_id, user_id, expires_at FROM memberships
			WHERE group_id = $1 ORDER BY user_id LIMIT $2`, groupID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT team_id, group_id, user_id, expires_at FROM memberships
			WHERE group_id = $1 AND user_id > $2 ORDER BY user_id LIMIT $3`, groupID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	memberships := make([]Membership, 0, limit)
	for rows.Next() {
		membership, err := scanMembership(rows)
		if err != nil {
			return nil, "", err
		}
		memberships = append(memberships, membership)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return memberships, nextCursor(len(memberships), limit, func(i int) string { return memberships[i].UserID }), nil
}

func scanTeam(row pgx.Row) (Team, error) {
	var team Team
	if err := row.Scan(&team.ID, &team.Slug, &team.Name, &team.Status, &team.CreatedAt); err != nil {
		return Team{}, err
	}
	return team, nil
}

func scanGroup(row pgx.Row) (Group, error) {
	var group Group
	if err := row.Scan(&group.ID, &group.TeamID, &group.Name); err != nil {
		return Group{}, err
	}
	return group, nil
}

func scanMembership(row pgx.Row) (Membership, error) {
	var membership Membership
	if err := row.Scan(&membership.TeamID, &membership.GroupID, &membership.UserID, &membership.ExpiresAt); err != nil {
		return Membership{}, err
	}
	return membership, nil
}
