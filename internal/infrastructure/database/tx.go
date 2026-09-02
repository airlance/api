package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type txContextKey struct{}

// TxManager provides an interface for executing operations within an atomic transaction.
type TxManager interface {
	WithTx(ctx context.Context, fn func(ctx context.Context) error) error
}

// PostgresTxManager implements TxManager using pgxpool.Pool.
type PostgresTxManager struct {
	pool *pgxpool.Pool
}

// NewTxManager constructs a PostgresTxManager.
func NewTxManager(pool *pgxpool.Pool) *PostgresTxManager {
	return &PostgresTxManager{pool: pool}
}

// WithTx executes the provided callback within a database transaction.
// If an active transaction already exists in ctx, it reuses it.
func (tm *PostgresTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	if _, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok {
		// Already in transaction, reuse
		return fn(ctx)
	}

	tx, err := tm.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("database: begin tx failed: %w", err)
	}

	txCtx := context.WithValue(ctx, txContextKey{}, tx)

	defer func() {
		_ = tx.Rollback(ctx)
	}()

	if err := fn(txCtx); err != nil {
		return err
	}

	if err := tx.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit tx failed: %w", err)
	}

	return nil
}

// GetExecutor returns the current transaction if present in context, or the fallback pool.
func GetExecutor(ctx context.Context, pool *pgxpool.Pool) DBExecutor {
	if tx, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok && tx != nil {
		return tx
	}
	return pool
}
