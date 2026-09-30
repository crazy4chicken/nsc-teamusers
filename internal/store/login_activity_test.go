package store

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"
	"time"
	"unicode/utf8"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
)

func TestSanitizeLoginActivityRemovesControls(t *testing.T) {
	activity := sanitizeLoginActivity(LoginActivity{
		AttemptedUsername: "ali\nce\t\x00",
		UserAgent:         "Example\r\nBrowser\t",
	})
	if activity.AttemptedUsername != "alice" {
		t.Fatalf("sanitized username = %q, want %q", activity.AttemptedUsername, "alice")
	}
	if activity.UserAgent != "ExampleBrowser" {
		t.Fatalf("sanitized user agent = %q, want %q", activity.UserAgent, "ExampleBrowser")
	}
}

func TestSanitizeLoginActivityUsesUTF8SafeByteLimits(t *testing.T) {
	activity := sanitizeLoginActivity(LoginActivity{
		AttemptedUsername: strings.Repeat("é", loginActivityUsernameMaxBytes/2) + "x",
		UserAgent:         strings.Repeat("x", loginActivityUserAgentMaxBytes) + "é",
	})
	if len(activity.AttemptedUsername) != loginActivityUsernameMaxBytes || activity.AttemptedUsername != strings.Repeat("é", loginActivityUsernameMaxBytes/2) {
		t.Fatalf("sanitized username = %q (%d bytes), want %d UTF-8-safe bytes", activity.AttemptedUsername, len(activity.AttemptedUsername), loginActivityUsernameMaxBytes)
	}
	if len(activity.UserAgent) != loginActivityUserAgentMaxBytes || activity.UserAgent != strings.Repeat("x", loginActivityUserAgentMaxBytes) {
		t.Fatalf("sanitized user agent has %d bytes, want %d", len(activity.UserAgent), loginActivityUserAgentMaxBytes)
	}
	if !utf8.ValidString(activity.AttemptedUsername) || !utf8.ValidString(activity.UserAgent) {
		t.Fatal("sanitized login activity metadata contains invalid UTF-8")
	}
}

type loginActivityRetentionCall struct {
	args []any
}

type loginActivityRetentionTestQuery struct {
	deletedRows []int64
	failCall    int
	calls       []loginActivityRetentionCall
	failure     error
}

func (q *loginActivityRetentionTestQuery) Exec(_ context.Context, _ string, args ...any) (pgconn.CommandTag, error) {
	q.calls = append(q.calls, loginActivityRetentionCall{args: append([]any(nil), args...)})
	callNumber := len(q.calls)
	if q.failCall == callNumber {
		return pgconn.NewCommandTag(""), q.failure
	}
	if callNumber > len(q.deletedRows) {
		return pgconn.NewCommandTag(""), errors.New("unexpected login activity retention batch")
	}
	if len(args) != 2 {
		return pgconn.NewCommandTag(""), errors.New("unexpected login activity retention arguments")
	}
	if _, ok := args[0].(time.Time); !ok {
		return pgconn.NewCommandTag(""), errors.New("unexpected login activity retention cutoff")
	}
	if limit, ok := args[1].(int); !ok || limit != loginActivityRetentionBatchSize {
		return pgconn.NewCommandTag(""), errors.New("unexpected login activity retention batch size")
	}
	return pgconn.NewCommandTag(fmt.Sprintf("DELETE %d", q.deletedRows[callNumber-1])), nil
}

func (*loginActivityRetentionTestQuery) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unexpected query")
}

func (*loginActivityRetentionTestQuery) QueryRow(context.Context, string, ...any) pgx.Row {
	panic("unexpected query row")
}

func TestDeleteExpiredLoginActivityDeletesInBoundedBatches(t *testing.T) {
	cutoff := time.Date(2026, time.January, 1, 12, 0, 0, 0, time.UTC)
	query := &loginActivityRetentionTestQuery{deletedRows: []int64{1000, 1000, 37}}
	deleted, err := DeleteExpiredLoginActivity(context.Background(), query, cutoff)
	if err != nil {
		t.Fatalf("delete expired login activity: %v", err)
	}
	if deleted != 2037 {
		t.Fatalf("deleted rows = %d, want 2037", deleted)
	}
	if len(query.calls) != 3 {
		t.Fatalf("delete batches = %d, want 3", len(query.calls))
	}
	for i, call := range query.calls {
		if !call.args[0].(time.Time).Equal(cutoff) || call.args[1] != loginActivityRetentionBatchSize {
			t.Fatalf("retention batch %d arguments = %v, want cutoff and batch size %d", i+1, call.args, loginActivityRetentionBatchSize)
		}
	}
}

func TestDeleteExpiredLoginActivityReturnsPartialCountOnError(t *testing.T) {
	failure := errors.New("database unavailable")
	query := &loginActivityRetentionTestQuery{
		deletedRows: []int64{loginActivityRetentionBatchSize},
		failCall:    2,
		failure:     failure,
	}
	deleted, err := DeleteExpiredLoginActivity(context.Background(), query, time.Now())
	if !errors.Is(err, failure) {
		t.Fatalf("delete expired login activity error = %v, want database error", err)
	}
	if deleted != loginActivityRetentionBatchSize {
		t.Fatalf("deleted rows before error = %d, want %d", deleted, loginActivityRetentionBatchSize)
	}
}
