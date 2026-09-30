package passwd

import (
	"context"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgtype"
)

func TestPasswordSetCheckAndRecordPhases(t *testing.T) {
	ctx := context.Background()
	now := time.Unix(2_000_000_000, 0)
	checkQ := &passwordSetTestQ{withHistoryPolicy: true}
	checked, err := CheckSet(ctx, checkQ, "usr_test", "PasswordWithDigit1", false, now)
	if err != nil {
		t.Fatalf("CheckSet() error = %v", err)
	}
	if checkQ.execCalls != 0 {
		t.Fatalf("CheckSet() executed %d writes, want none", checkQ.execCalls)
	}
	if !Verify(checked.Hash, "PasswordWithDigit1") {
		t.Fatal("CheckSet() hash does not verify against the checked password")
	}

	recordQ := &passwordSetTestQ{}
	if err := RecordSet(ctx, recordQ, checked); err != nil {
		t.Fatalf("RecordSet() error = %v", err)
	}
	if recordQ.execCalls != 2 {
		t.Fatalf("RecordSet() executed %d writes, want history insert and retention prune", recordQ.execCalls)
	}
}

type passwordSetTestQ struct {
	withHistoryPolicy bool
	queryCalls        int
	rowCalls          int
	execCalls         int
}

func (q *passwordSetTestQ) Exec(context.Context, string, ...any) (pgconn.CommandTag, error) {
	q.execCalls++
	return pgconn.NewCommandTag("INSERT 0 1"), nil
}

func (q *passwordSetTestQ) Query(context.Context, string, ...any) (pgx.Rows, error) {
	q.queryCalls++
	if q.withHistoryPolicy && q.queryCalls == 1 {
		return &passwordPolicyRows{next: true}, nil
	}
	return &passwordPolicyRows{}, nil
}

func (q *passwordSetTestQ) QueryRow(context.Context, string, ...any) pgx.Row {
	q.rowCalls++
	if q.withHistoryPolicy || q.rowCalls > 1 {
		return passwordSetTestRow{noRows: true}
	}
	return passwordSetTestRow{}
}

type passwordSetTestRow struct {
	noRows bool
}

func (r passwordSetTestRow) Scan(dest ...any) error {
	if r.noRows {
		return pgx.ErrNoRows
	}
	if len(dest) != 1 {
		return nil
	}
	if value, ok := dest[0].(*string); ok {
		*value = "usr_test"
	}
	return nil
}

type passwordPolicyRows struct {
	next bool
}

func (r *passwordPolicyRows) TypeMap() *pgtype.Map                         { return pgtype.NewMap() }
func (r *passwordPolicyRows) Close()                                       {}
func (r *passwordPolicyRows) Err() error                                   { return nil }
func (r *passwordPolicyRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *passwordPolicyRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *passwordPolicyRows) Next() bool {
	if !r.next {
		return false
	}
	r.next = false
	return true
}
func (r *passwordPolicyRows) Scan(dest ...any) error {
	if len(dest) != 15 {
		return nil
	}
	*dest[0].(*string) = "policy"
	*dest[1].(*string) = "history"
	*dest[2].(*int) = 1
	*dest[3].(*string) = "user"
	*dest[4].(*string) = "usr_test"
	*dest[5].(*pgtype.Int4) = pgtype.Int4{}
	for _, index := range []int{6, 7, 8, 9, 10} {
		*dest[index].(*pgtype.Bool) = pgtype.Bool{}
	}
	*dest[11].(*pgtype.Int4) = pgtype.Int4{Int32: 1, Valid: true}
	*dest[12].(*pgtype.Bool) = pgtype.Bool{}
	*dest[13].(*time.Time) = time.Time{}
	*dest[14].(*time.Time) = time.Time{}
	return nil
}
func (r *passwordPolicyRows) Values() ([]any, error) { return nil, nil }
func (r *passwordPolicyRows) RawValues() [][]byte    { return nil }
func (r *passwordPolicyRows) Conn() *pgx.Conn        { return nil }
