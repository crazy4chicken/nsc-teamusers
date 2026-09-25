package store

import (
	"context"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func CreateUser(ctx context.Context, q Q, user User) (User, error) {
	if user.ID == "" {
		user.ID = NewID()
	}
	return scanUser(q.QueryRow(ctx, `
		INSERT INTO users (id, username, email, display_name, status)
		VALUES ($1, $2, $3, $4, $5)
		RETURNING id, username, email, display_name, status, perm_ver, email_verified_at, approved_at, approved_by, created_at, updated_at`,
		user.ID, user.Username, user.Email, user.DisplayName, user.Status))
}

func GetUser(ctx context.Context, q Q, id string) (User, error) {
	return scanUser(q.QueryRow(ctx, `
        SELECT id, username, email, display_name, status, perm_ver, email_verified_at, approved_at, approved_by, created_at, updated_at
        FROM users WHERE id = $1`, id))
}

func ListUsers(ctx context.Context, q Q, cursor string, limit int) ([]User, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
            SELECT id, username, email, display_name, status, perm_ver, email_verified_at, approved_at, approved_by, created_at, updated_at
            FROM users ORDER BY id LIMIT $1`, limit)
	} else {
		rows, err = q.Query(ctx, `
            SELECT id, username, email, display_name, status, perm_ver, email_verified_at, approved_at, approved_by, created_at, updated_at
            FROM users WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	users := make([]User, 0, limit)
	for rows.Next() {
		user, err := scanUser(rows)
		if err != nil {
			return nil, "", err
		}
		users = append(users, user)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return users, nextCursor(len(users), limit, func(i int) string { return users[i].ID }), nil
}

func UpdateUser(ctx context.Context, q Q, user User) (User, error) {
	return scanUser(q.QueryRow(ctx, `
        UPDATE users
        SET username = $2, email = $3, display_name = $4, status = $5, updated_at = now()
        WHERE id = $1
        RETURNING id, username, email, display_name, status, perm_ver, email_verified_at, approved_at, approved_by, created_at, updated_at`,
		user.ID, user.Username, user.Email, user.DisplayName, user.Status))
}

func DeleteUser(ctx context.Context, q Q, id string) error {
	_, err := q.Exec(ctx, `DELETE FROM users WHERE id = $1`, id)
	return err
}

func CreateCredential(ctx context.Context, q Q, credential Credential) (Credential, error) {
	return scanCredential(q.QueryRow(ctx, `
		INSERT INTO credentials (user_id, kind, hash, rotated_at)
		VALUES ($1, $2, $3, $4)
		RETURNING user_id, kind, hash, created_at, rotated_at`,
		credential.UserID, credential.Kind, credential.Hash, credential.RotatedAt))
}

func GetCredential(ctx context.Context, q Q, userID, kind string) (Credential, error) {
	return scanCredential(q.QueryRow(ctx, `
		SELECT user_id, kind, hash, created_at, rotated_at
		FROM credentials WHERE user_id = $1 AND kind = $2`, userID, kind))
}

func ListCredentials(ctx context.Context, q Q, userID, cursor string, limit int) ([]Credential, string, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor == "" {
		rows, err = q.Query(ctx, `
			SELECT user_id, kind, hash, created_at, rotated_at
			FROM credentials WHERE user_id = $1 ORDER BY kind LIMIT $2`, userID, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT user_id, kind, hash, created_at, rotated_at
			FROM credentials WHERE user_id = $1 AND kind > $2 ORDER BY kind LIMIT $3`, userID, cursor, limit)
	}
	if err != nil {
		return nil, "", err
	}
	defer rows.Close()
	credentials := make([]Credential, 0, limit)
	for rows.Next() {
		credential, err := scanCredential(rows)
		if err != nil {
			return nil, "", err
		}
		credentials = append(credentials, credential)
	}
	if err := rows.Err(); err != nil {
		return nil, "", err
	}
	return credentials, nextCursor(len(credentials), limit, func(i int) string { return credentials[i].Kind }), nil
}

func UpdateCredential(ctx context.Context, q Q, credential Credential) (Credential, error) {
	return scanCredential(q.QueryRow(ctx, `
		UPDATE credentials SET hash = $3, rotated_at = $4
		WHERE user_id = $1 AND kind = $2
		RETURNING user_id, kind, hash, created_at, rotated_at`,
		credential.UserID, credential.Kind, credential.Hash, credential.RotatedAt))
}

func DeleteCredential(ctx context.Context, q Q, userID, kind string) error {
	_, err := q.Exec(ctx, `DELETE FROM credentials WHERE user_id = $1 AND kind = $2`, userID, kind)
	return err
}

func scanUser(row pgx.Row) (User, error) {
	var user User
	var email, approvedBy pgtype.Text
	var emailVerifiedAt, approvedAt pgtype.Timestamptz
	if err := row.Scan(
		&user.ID, &user.Username, &email, &user.DisplayName, &user.Status,
		&user.PermVer, &emailVerifiedAt, &approvedAt, &approvedBy,
		&user.CreatedAt, &user.UpdatedAt,
	); err != nil {
		return User{}, err
	}
	user.Email = textPointer(email)
	user.EmailVerifiedAt = timePointer(emailVerifiedAt)
	user.ApprovedAt = timePointer(approvedAt)
	user.ApprovedBy = textPointer(approvedBy)
	return user, nil
}

func scanCredential(row pgx.Row) (Credential, error) {
	var credential Credential
	if err := row.Scan(
		&credential.UserID, &credential.Kind, &credential.Hash,
		&credential.CreatedAt, &credential.RotatedAt,
	); err != nil {
		return Credential{}, err
	}
	return credential, nil
}

func textPointer(value pgtype.Text) *string {
	if !value.Valid {
		return nil
	}
	result := value.String
	return &result
}

func timePointer(value pgtype.Timestamptz) *time.Time {
	if !value.Valid {
		return nil
	}
	result := value.Time
	return &result
}

func nextCursor(length, limit int, value func(int) string) string {
	if length == 0 || length < limit {
		return ""
	}
	return value(length - 1)
}
