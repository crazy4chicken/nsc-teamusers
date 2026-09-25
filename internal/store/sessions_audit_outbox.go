package store

import (
	"context"
	"encoding/json"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgtype"
)

func CreateSession(ctx context.Context, q Q, session Session) (Session, error) {
	if session.ID == "" {
		session.ID = NewID()
	}
	if session.CreatedAt.IsZero() {
		session.CreatedAt = time.Now().UTC()
	}
	clientMeta := []byte(session.ClientMeta)
	if len(clientMeta) == 0 {
		clientMeta = []byte(`{}`)
	}
	return scanSession(q.QueryRow(ctx, `
		INSERT INTO sessions (id, user_id, family_id, client_meta, created_at, expires_at, family_not_after, revoked_at, revoke_reason)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)
		RETURNING id, user_id, family_id, client_meta, created_at, expires_at, family_not_after, revoked_at, revoke_reason`,
		session.ID, session.UserID, session.FamilyID, clientMeta, session.CreatedAt, session.ExpiresAt,
		session.FamilyNotAfter, session.RevokedAt, session.RevokeReason))
}

func GetSession(ctx context.Context, q Q, id string) (Session, error) {
	return scanSession(q.QueryRow(ctx, `
		SELECT id, user_id, family_id, client_meta, created_at, expires_at, family_not_after, revoked_at, revoke_reason
		FROM sessions WHERE id = $1`, id))
}

// ListSessionsByUser returns active, unexpired refresh-token sessions for a user.
func ListSessionsByUser(ctx context.Context, q Q, userID string) ([]Session, error) {
	rows, err := q.Query(ctx, `
		SELECT id, user_id, family_id, client_meta, created_at, expires_at, family_not_after, revoked_at, revoke_reason
		FROM sessions
		WHERE user_id = $1 AND revoked_at IS NULL AND expires_at > now()
		ORDER BY created_at, id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	sessions := make([]Session, 0)
	for rows.Next() {
		session, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		sessions = append(sessions, session)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return sessions, nil
}

// DeleteSessionForUser revokes one unrevoked session only when it belongs to
// userID. The rows-affected result is zero for unknown, foreign, or revoked
// sessions, allowing callers to return a non-leaking 404.
func DeleteSessionForUser(ctx context.Context, q Q, sessionID, userID string) (int64, error) {
	result, err := q.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'user_requested'
		WHERE id = $1 AND user_id = $2 AND revoked_at IS NULL`, sessionID, userID)
	if err != nil {
		return 0, err
	}
	return result.RowsAffected(), nil
}

// DeleteAllSessionsForUser revokes every unrevoked session belonging to userID.
func DeleteAllSessionsForUser(ctx context.Context, q Q, userID string) error {
	_, err := q.Exec(ctx, `
		UPDATE sessions
		SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = 'user_requested'
		WHERE user_id = $1 AND revoked_at IS NULL`, userID)
	return err
}

func RevokeSessionFamily(ctx context.Context, q Q, familyID, reason string) error {
	_, err := q.Exec(ctx, `
		UPDATE sessions SET revoked_at = COALESCE(revoked_at, now()), revoke_reason = $2
		WHERE family_id = $1 AND revoked_at IS NULL`, familyID, reason)
	return err
}

func scanSession(row pgx.Row) (Session, error) {
	var session Session
	var clientMeta []byte
	var reason pgtype.Text
	if err := row.Scan(
		&session.ID, &session.UserID, &session.FamilyID, &clientMeta,
		&session.CreatedAt, &session.ExpiresAt, &session.FamilyNotAfter, &session.RevokedAt, &reason,
	); err != nil {
		return Session{}, err
	}
	session.ClientMeta = json.RawMessage(clientMeta)
	session.RevokeReason = textPointer(reason)
	return session, nil
}

func AppendAuditLog(ctx context.Context, q Q, entry AuditEntry) (AuditEntry, error) {
	diff := []byte(entry.Diff)
	if len(diff) == 0 {
		diff = []byte(`{}`)
	}
	return scanAuditEntry(q.QueryRow(ctx, `
		INSERT INTO audit_log (team_id, actor_id, action, target, diff, request_id)
		VALUES ($1, $2, $3, $4, $5, $6)
		RETURNING id, team_id, actor_id, action, target, diff, request_id, at`,
		entry.TeamID, entry.ActorID, entry.Action, entry.Target, diff, entry.RequestID))
}

func ListAuditLog(ctx context.Context, q Q, teamID *string, cursor int64, limit int) ([]AuditEntry, int64, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	switch {
	case teamID == nil && cursor <= 0:
		rows, err = q.Query(ctx, `
			SELECT id, team_id, actor_id, action, target, diff, request_id, at
			FROM audit_log ORDER BY id LIMIT $1`, limit)
	case teamID == nil:
		rows, err = q.Query(ctx, `
			SELECT id, team_id, actor_id, action, target, diff, request_id, at
			FROM audit_log WHERE id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	case cursor <= 0:
		rows, err = q.Query(ctx, `
			SELECT id, team_id, actor_id, action, target, diff, request_id, at
			FROM audit_log WHERE team_id IS NOT DISTINCT FROM $1 ORDER BY id LIMIT $2`, *teamID, limit)
	default:
		rows, err = q.Query(ctx, `
			SELECT id, team_id, actor_id, action, target, diff, request_id, at
			FROM audit_log WHERE team_id IS NOT DISTINCT FROM $1 AND id > $2 ORDER BY id LIMIT $3`, *teamID, cursor, limit)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	entries := make([]AuditEntry, 0, limit)
	for rows.Next() {
		entry, err := scanAuditEntry(rows)
		if err != nil {
			return nil, 0, err
		}
		entries = append(entries, entry)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(entries) == limit {
		return entries, entries[len(entries)-1].ID, nil
	}
	return entries, 0, nil
}

func scanAuditEntry(row pgx.Row) (AuditEntry, error) {
	var entry AuditEntry
	var teamID, actorID, requestID pgtype.Text
	if err := row.Scan(
		&entry.ID, &teamID, &actorID, &entry.Action, &entry.Target,
		&entry.Diff, &requestID, &entry.At,
	); err != nil {
		return AuditEntry{}, err
	}
	entry.TeamID = textPointer(teamID)
	entry.ActorID = textPointer(actorID)
	entry.RequestID = textPointer(requestID)
	return entry, nil
}

func AppendOutboxEvent(ctx context.Context, q Q, event OutboxEvent) (OutboxEvent, error) {
	payload := []byte(event.Payload)
	if len(payload) == 0 {
		payload = []byte(`{}`)
	}
	return scanOutboxEvent(q.QueryRow(ctx, `
		INSERT INTO outbox (topic, payload, published_at)
		VALUES ($1, $2, $3)
		RETURNING id, topic, payload, published_at`, event.Topic, payload, event.PublishedAt))
}

func FetchUnpublishedOutbox(ctx context.Context, q Q, cursor int64, limit int) ([]OutboxEvent, int64, error) {
	limit = pageLimit(limit)
	var rows pgx.Rows
	var err error
	if cursor <= 0 {
		rows, err = q.Query(ctx, `
			SELECT id, topic, payload, published_at FROM outbox
			WHERE published_at IS NULL ORDER BY id LIMIT $1`, limit)
	} else {
		rows, err = q.Query(ctx, `
			SELECT id, topic, payload, published_at FROM outbox
			WHERE published_at IS NULL AND id > $1 ORDER BY id LIMIT $2`, cursor, limit)
	}
	if err != nil {
		return nil, 0, err
	}
	defer rows.Close()
	events := make([]OutboxEvent, 0, limit)
	for rows.Next() {
		event, err := scanOutboxEvent(rows)
		if err != nil {
			return nil, 0, err
		}
		events = append(events, event)
	}
	if err := rows.Err(); err != nil {
		return nil, 0, err
	}
	if len(events) == limit {
		return events, events[len(events)-1].ID, nil
	}
	return events, 0, nil
}

func MarkOutboxPublished(ctx context.Context, q Q, ids []int64, publishedAt time.Time) error {
	if len(ids) == 0 {
		return nil
	}
	if publishedAt.IsZero() {
		_, err := q.Exec(ctx, `UPDATE outbox SET published_at = now() WHERE id = ANY($1::bigint[])`, ids)
		return err
	}
	_, err := q.Exec(ctx, `UPDATE outbox SET published_at = $2 WHERE id = ANY($1::bigint[])`, ids, publishedAt)
	return err
}

func scanOutboxEvent(row pgx.Row) (OutboxEvent, error) {
	var event OutboxEvent
	if err := row.Scan(&event.ID, &event.Topic, &event.Payload, &event.PublishedAt); err != nil {
		return OutboxEvent{}, err
	}
	return event, nil
}
