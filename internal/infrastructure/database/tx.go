package database

import (
	"context"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/tx"
)

type txContextKey struct{}

// TxManager alias for backward compatibility.
type TxManager = tx.TxManager

// PostgresTxManager implements tx.TxManager using pgxpool.Pool.
type PostgresTxManager struct {
	pool *pgxpool.Pool
}

// Ensure PostgresTxManager implements tx.TxManager.
var _ tx.TxManager = (*PostgresTxManager)(nil)

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

	txInstance, err := tm.pool.BeginTx(ctx, pgx.TxOptions{})
	if err != nil {
		return fmt.Errorf("database: begin tx failed: %w", err)
	}

	txCtx := context.WithValue(ctx, txContextKey{}, txInstance)

	defer func() {
		_ = txInstance.Rollback(ctx)
	}()

	if err := fn(txCtx); err != nil {
		return err
	}

	if err := txInstance.Commit(ctx); err != nil {
		return fmt.Errorf("database: commit tx failed: %w", err)
	}

	return nil
}

// GetExecutor returns the current transaction if present in context, or the fallback pool.
func GetExecutor(ctx context.Context, pool *pgxpool.Pool) DBExecutor {
	if txInstance, ok := ctx.Value(txContextKey{}).(pgx.Tx); ok && txInstance != nil {
		return txInstance
	}
	return pool
}
