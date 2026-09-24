package store

import (
	"context"
	"errors"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

// WithAdminTx runs an admin mutation and its audit append in one transaction.
// The production query handle is a *pgxpool.Pool; the Begin-capable fallback
// keeps the helper usable with pool wrappers without giving handlers direct
// access to pgx transactions.
func WithAdminTx(ctx context.Context, q Q, fn func(context.Context, Tx) error) error {
	if q == nil {
		return errors.New("query handle must not be nil")
	}
	if fn == nil {
		return errors.New("transaction callback must not be nil")
	}
	if pool, ok := q.(*pgxpool.Pool); ok {
		return WithTx(ctx, pool, fn)
	}
	beginner, ok := q.(interface {
		Begin(context.Context) (pgx.Tx, error)
	})
	if !ok {
		return errors.New("query handle does not support transactions")
	}
	tx, err := beginner.Begin(ctx)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback(ctx) }()
	if err := fn(ctx, tx); err != nil {
		return err
	}
	return tx.Commit(ctx)
}
