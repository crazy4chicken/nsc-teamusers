package store

import (
	"context"
	"errors"
	"strings"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

const scimUserColumns = `id, username, email, display_name, status, external_id, perm_ver, failed_logins, locked_until, email_verified_at, approved_at, approved_by, created_at, updated_at`

// SCIMUser pairs the internal user record with its SCIM external identifier.
type SCIMUser struct {
	User
	ExternalID *string `json:"external_id,omitempty"`
}

// CreateSCIMUser creates a user and stores its client-provided external ID.
func CreateSCIMUser(ctx context.Context, q Q, user User, externalID *string) (SCIMUser, error) {
	if user.ID == "" {
		user.ID = NewID()
	}
	user.Username = strings.ToLower(strings.TrimSpace(user.Username))
	if user.Status == "" {
		user.Status = "active"
	}
	return scanSCIMUser(q.QueryRow(ctx, `
		INSERT INTO users (id, username, email, display_name, status, external_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING `+scimUserColumns,
		user.ID, user.Username, user.Email, user.DisplayName, user.Status, externalID))
}

// GetSCIMUser reads a user with its SCIM external identifier.
func GetSCIMUser(ctx context.Context, q Q, id string) (SCIMUser, error) {
	return scanSCIMUser(q.QueryRow(ctx, `
		SELECT `+scimUserColumns+`
		FROM users WHERE id = $1 AND external_id IS NOT NULL`, id))
}

// ListSCIMUsers returns an offset-paginated user page and its total result count.
func ListSCIMUsers(ctx context.Context, q Q, userName *string, startIndex, count int) ([]SCIMUser, int64, error) {
	if startIndex < 1 || count < 0 {
		return nil, 0, errors.New("invalid SCIM page")
	}
	if count > 1000 {
		count = 1000
	}

	var total int64
	var err error
	if userName == nil {
		err = q.QueryRow(ctx, `SELECT count(*) FROM users WHERE external_id IS NOT NULL AND left(lower(username), 8) <> 'deleted_'`).Scan(&total)
	} else {
		err = q.QueryRow(ctx, `SELECT count(*) FROM users WHERE external_id IS NOT NULL AND left(lower(username), 8) <> 'deleted_' AND username = $1`, *userName).Scan(&total)
	}
	if err != nil {
		return nil, 0, err
	}
	users := make([]SCIMUser, 0, count)
	if count == 0 {
		return users, total, nil
	}

	var rows pgx.Rows
	if userName == nil {
		rows, err = q.Query(ctx, `
			SELECT `+scimUserColumns+`
			FROM users WHERE external_id IS NOT NULL AND left(lower(username), 8) <> 'deleted_' ORDER BY id LIMIT $1 OFFSET $2`, count, startIndex-1)
	} else {
		rows, err = q.Query(ctx, `
			SELECT `+scimUserColumns+`
			FROM users WHERE external_id IS NOT NULL AND left(lower(username), 8) <> 'deleted_' AND username = $1 ORDER BY id LIMIT $2 OFFSET $3`, *userName, count, startIndex-1)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	for rows.Next() {
		user, err := scanSCIMUser(rows)
		if err != nil {
			return nil, 0, err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	return users, total, nil
}

// UpdateSCIMUser replaces SCIM-managed profile fields and external ID.
// A changed email address loses any verification timestamp associated with the old address.
func UpdateSCIMUser(ctx context.Context, q Q, user User, externalID *string) (SCIMUser, error) {
	user.Username = strings.ToLower(strings.TrimSpace(user.Username))
	return scanSCIMUser(q.QueryRow(ctx, `
		UPDATE users
		SET username = $2,
			email_verified_at = CASE WHEN email IS DISTINCT FROM $3 THEN NULL ELSE email_verified_at END,
			email = $3,
			display_name = $4,
			status = $5,
			external_id = COALESCE($6, external_id),
			updated_at = now()
		WHERE id = $1 AND external_id IS NOT NULL AND left(lower(username), 8) <> 'deleted_'
		RETURNING `+scimUserColumns,
		user.ID, user.Username, user.Email, user.DisplayName, user.Status, externalID))
}

func scanSCIMUser(row pgx.Row) (SCIMUser, error) {
	var result SCIMUser
	var email, externalID, approvedBy pgtype.Text
	var lockedUntil, emailVerifiedAt, approvedAt pgtype.Timestamptz
	user := &result.User
	if err := row.Scan(
		&user.ID, &user.Username, &email, &user.DisplayName, &user.Status, &externalID,
		&user.PermVer, &user.FailedLogins, &lockedUntil, &emailVerifiedAt, &approvedAt, &approvedBy,
		&user.CreatedAt, &user.UpdatedAt,
	); err != nil {
		return SCIMUser{}, err
	}
	user.Email = textPointer(email)
	user.LockedUntil = timePointer(lockedUntil)
	user.EmailVerifiedAt = timePointer(emailVerifiedAt)
	user.ApprovedAt = timePointer(approvedAt)
	user.ApprovedBy = textPointer(approvedBy)
	result.ExternalID = textPointer(externalID)
	return result, nil
}
