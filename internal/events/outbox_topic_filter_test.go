package events

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

type outboxTopicFilterTestQuery struct {
	query string
	args  []any
	calls int
}

func (q *outboxTopicFilterTestQuery) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	return pgconn.NewCommandTag(""), errors.New("unexpected exec")
}

func (q *outboxTopicFilterTestQuery) Query(_ context.Context, query string, args ...any) (pgx.Rows, error) {
	q.query = query
	q.args = append([]any(nil), args...)
	q.calls++
	return &emptyOutboxTopicFilterRows{}, nil
}

func (*outboxTopicFilterTestQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected query row")
}

type emptyOutboxTopicFilterRows struct {
	pgx.Rows
}

func (*emptyOutboxTopicFilterRows) Close()         {}
func (*emptyOutboxTopicFilterRows) Err() error     { return nil }
func (*emptyOutboxTopicFilterRows) Next() bool     { return false }

func TestRelayFetchesOnlySupportedOutboxTopics(t *testing.T) {
	query := &outboxTopicFilterTestQuery{}
	relay := &Relay{q: query}
	if err := relay.publishBatch(context.Background(), nil, nil); err != nil {
		t.Fatalf("fetch relay outbox batch: %v", err)
	}
	if query.calls != 1 || !strings.Contains(query.query, "topic = ANY($1::text[])") {
		t.Fatalf("relay fetch query = %q, want a topic-filtered outbox query", query.query)
	}
	gotTopics, ok := query.args[0].([]string)
	if !ok {
		t.Fatalf("relay topic argument = %T, want []string", query.args[0])
	}
	wantTopics := map[string]bool{
		"perm.changed": true,
		"user.disabled": true,
		"role.updated": true,
		"key.rotated": true,
	}
	if len(gotTopics) != len(wantTopics) {
		t.Fatalf("relay topics = %v, want only %v", gotTopics, wantTopics)
	}
	for _, topic := range gotTopics {
		if !wantTopics[topic] {
			t.Fatalf("relay fetched unexpected topic %q", topic)
		}
		delete(wantTopics, topic)
	}
	if len(wantTopics) != 0 {
		t.Fatalf("relay omitted supported topics: %v", wantTopics)
	}
}

func TestNotifierFetchesOnlyNotificationTopics(t *testing.T) {
	query := &outboxTopicFilterTestQuery{}
	notifier := &Notifier{q: query}
	if err := notifier.dispatchBatch(context.Background()); err != nil {
		t.Fatalf("fetch notifier outbox batch: %v", err)
	}
	if query.calls != 1 || !strings.Contains(query.query, "topic LIKE $1") {
		t.Fatalf("notifier fetch query = %q, want a topic-filtered outbox query", query.query)
	}
	if len(query.args) == 0 || query.args[0] != "notify.%" {
		t.Fatalf("notifier topic pattern = %v, want notify.%%", query.args)
	}
}
