package store

import (
	"context"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/oklog/ulid/v2"
)

// Q is the small query surface shared by pgxpool.Pool and pgx.Tx.
type Q interface {
	Exec(context.Context, string, ...any) (pgconn.CommandTag, error)
	Query(context.Context, string, ...any) (pgx.Rows, error)
	QueryRow(context.Context, string, ...any) pgx.Row
}

// Tx is the query surface plus transaction completion methods.
type Tx interface {
	Q
	Commit(context.Context) error
	Rollback(context.Context) error
}

// NewPool parses the connection string and opens a pgx connection pool. The
// caller owns the returned pool and must call Close when it is done.
func NewPool(ctx context.Context, connectionString string) (*pgxpool.Pool, error) {
	if connectionString == "" {
		return nil, errors.New("connection string must not be empty")
	}
	poolConfig, err := pgxpool.ParseConfig(connectionString)
	if err != nil {
		return nil, fmt.Errorf("parse connection string: %w", err)
	}
	pool, err := pgxpool.NewWithConfig(ctx, poolConfig)
	if err != nil {
		return nil, fmt.Errorf("open PostgreSQL pool: %w", err)
	}
	return pool, nil
}

// WithTx executes fn in a transaction and rolls back on every error path.
func WithTx(ctx context.Context, pool *pgxpool.Pool, fn func(context.Context, Tx) error) error {
	if pool == nil {
		return errors.New("pool must not be nil")
	}
	if fn == nil {
		return errors.New("transaction callback must not be nil")
	}
	tx, err := pool.Begin(ctx)
	if err != nil {
		return fmt.Errorf("begin transaction: %w", err)
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("commit transaction: %w", err)
	}
	return nil
}

// NewID creates the application-side ULID used by text primary keys.
func NewID() string {
	return ulid.Make().String()
}

func pageLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}
