package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/account"
)

type AccountRepository struct {
	db *sql.DB
}

var _ account.Repository = (*AccountRepository)(nil)

func NewAccountRepository(db *sql.DB) *AccountRepository {
	return &AccountRepository{db: db}
}

func (r *AccountRepository) CreateAccount(ctx context.Context, email, firstName, lastName string) (account.Account, error) {
	query := `
		INSERT INTO accounts (email, first_name, last_name)
		VALUES ($1, $2, $3)
		RETURNING id, email, first_name, last_name, confirmed, session_ttl_months, created_at
	`
	var acc account.Account
	var sessionTTL sql.NullInt32
	err := r.db.QueryRowContext(ctx, query, email, firstName, lastName).Scan(
		&acc.ID,
		&acc.Email,
		&acc.FirstName,
		&acc.LastName,
		&acc.Confirmed,
		&sessionTTL,
		&acc.CreatedAt,
	)
	if err != nil {
		return account.Account{}, fmt.Errorf("postgres: create account failed: %w", err)
	}
	if sessionTTL.Valid {
		val := int(sessionTTL.Int32)
		acc.SessionTTLMonths = &val
	}
	return acc, nil
}

func (r *AccountRepository) FindByEmail(ctx context.Context, email string) (account.Account, error) {
	query := `
		SELECT id, email, first_name, last_name, confirmed, session_ttl_months, created_at
		FROM accounts
		WHERE email = $1
	`
	var acc account.Account
	var sessionTTL sql.NullInt32
	err := r.db.QueryRowContext(ctx, query, email).Scan(
		&acc.ID,
		&acc.Email,
		&acc.FirstName,
		&acc.LastName,
		&acc.Confirmed,
		&sessionTTL,
		&acc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return account.Account{}, account.ErrAccountNotFound
		}
		return account.Account{}, fmt.Errorf("postgres: find account by email failed: %w", err)
	}
	if sessionTTL.Valid {
		val := int(sessionTTL.Int32)
		acc.SessionTTLMonths = &val
	}
	return acc, nil
}

func (r *AccountRepository) FindByID(ctx context.Context, id account.AccountID) (account.Account, error) {
	query := `
		SELECT id, email, first_name, last_name, confirmed, session_ttl_months, created_at
		FROM accounts
		WHERE id = $1
	`
	var acc account.Account
	var sessionTTL sql.NullInt32
	err := r.db.QueryRowContext(ctx, query, id).Scan(
		&acc.ID,
		&acc.Email,
		&acc.FirstName,
		&acc.LastName,
		&acc.Confirmed,
		&sessionTTL,
		&acc.CreatedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return account.Account{}, account.ErrAccountNotFound
		}
		return account.Account{}, fmt.Errorf("postgres: find account by id failed: %w", err)
	}
	if sessionTTL.Valid {
		val := int(sessionTTL.Int32)
		acc.SessionTTLMonths = &val
	}
	return acc, nil
}

func (r *AccountRepository) ConfirmAccount(ctx context.Context, id account.AccountID) error {
	query := `
		UPDATE accounts
		SET confirmed = TRUE
		WHERE id = $1
	`
	res, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("postgres: confirm account failed: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: check rows affected failed: %w", err)
	}
	if affected == 0 {
		return account.ErrAccountNotFound
	}
	return nil
}

func (r *AccountRepository) SetSessionTTLMonths(ctx context.Context, id account.AccountID, months *int) error {
	query := `
		UPDATE accounts
		SET session_ttl_months = $1
		WHERE id = $2
	`
	var dbVal sql.NullInt32
	if months != nil {
		dbVal = sql.NullInt32{Int32: int32(*months), Valid: true}
	}

	res, err := r.db.ExecContext(ctx, query, dbVal, id)
	if err != nil {
		return fmt.Errorf("postgres: set session ttl failed: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return fmt.Errorf("postgres: check rows affected failed: %w", err)
	}
	if affected == 0 {
		return account.ErrAccountNotFound
	}
	return nil
}
