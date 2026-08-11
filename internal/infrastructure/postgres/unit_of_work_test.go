package postgres

import (
	"context"
	"errors"
	"testing"

	"github.com/DATA-DOG/go-sqlmock"
	"github.com/airlance/api/internal/usecase"
)

func TestUnitOfWork_CommitsOnSuccess(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	uow := NewUnitOfWork(db)

	mock.ExpectBegin()
	mock.ExpectCommit()

	err = uow.Execute(context.Background(), func(ctx context.Context, s usecase.TxStore) error {
		if s.Messages == nil || s.Updates == nil {
			t.Fatal("expected non-nil repositories in TxStore")
		}
		return nil
	})

	if err != nil {
		t.Fatalf("expected no error, got: %v", err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}

func TestUnitOfWork_RollsBackOnError(t *testing.T) {
	db, mock, err := sqlmock.New()
	if err != nil {
		t.Fatalf("failed to create sqlmock: %v", err)
	}
	defer db.Close()

	uow := NewUnitOfWork(db)

	dummyErr := errors.New("something went wrong")

	mock.ExpectBegin()
	mock.ExpectRollback()

	err = uow.Execute(context.Background(), func(ctx context.Context, s usecase.TxStore) error {
		return dummyErr
	})

	if !errors.Is(err, dummyErr) {
		t.Fatalf("expected error %v, got: %v", dummyErr, err)
	}

	if err := mock.ExpectationsWereMet(); err != nil {
		t.Fatalf("unmet expectations: %v", err)
	}
}
