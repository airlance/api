package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/usecase"
)

type UnitOfWork struct {
	db *sql.DB
}

var _ usecase.UnitOfWork = (*UnitOfWork)(nil)

func NewUnitOfWork(db *sql.DB) *UnitOfWork {
	return &UnitOfWork{db: db}
}

func (u *UnitOfWork) Execute(ctx context.Context, fn func(ctx context.Context, s usecase.TxStore) error) error {
	tx, err := u.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: begin tx failed: %w", err)
	}

	defer func(tx *sql.Tx) {
		err := tx.Rollback()
		if err != nil && !errors.Is(err, sql.ErrTxDone) {
			fmt.Printf("postgres: rollback failed: %v\n", err)
		}
	}(tx)

	store := usecase.TxStore{
		Messages: NewMessageRepository(tx),
		Updates:  NewUpdateLogRepository(tx),
	}

	if err := fn(ctx, store); err != nil {
		return err
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit tx failed: %w", err)
	}
	return nil
}
