package postgres

import (
	"bytes"
	"context"
	"database/sql"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/account"
)

type ConfirmationCodeRepository struct {
	db *sql.DB
}

var _ account.ConfirmationCodeRepository = (*ConfirmationCodeRepository)(nil)

func NewConfirmationCodeRepository(db *sql.DB) *ConfirmationCodeRepository {
	return &ConfirmationCodeRepository{db: db}
}

func (r *ConfirmationCodeRepository) SaveCode(ctx context.Context, accountID account.AccountID, codeHash []byte, expiresAt time.Time) error {
	query := `
		INSERT INTO email_confirmation_codes (account_id, code_hash, expires_at, attempts)
		VALUES ($1, $2, $3, 0)
		ON CONFLICT (account_id) DO UPDATE
		SET code_hash = EXCLUDED.code_hash,
		    expires_at = EXCLUDED.expires_at,
		    attempts = 0
	`
	_, err := r.db.ExecContext(ctx, query, accountID, codeHash, expiresAt)
	if err != nil {
		return fmt.Errorf("postgres: save confirmation code failed: %w", err)
	}
	return nil
}

func (r *ConfirmationCodeRepository) ConsumeCode(ctx context.Context, accountID account.AccountID, codeHash []byte) error {
	tx, err := r.db.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("postgres: begin tx failed: %w", err)
	}
	defer tx.Rollback()

	query := `
		SELECT code_hash, expires_at, attempts
		FROM email_confirmation_codes
		WHERE account_id = $1
		FOR UPDATE
	`
	var storedHash []byte
	var expiresAt time.Time
	var attempts int

	err = tx.QueryRowContext(ctx, query, accountID).Scan(&storedHash, &expiresAt, &attempts)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return account.ErrInvalidCode
		}
		return fmt.Errorf("postgres: query code failed: %w", err)
	}

	if attempts >= 5 {
		return account.ErrTooManyAttempts
	}

	if time.Now().After(expiresAt) {
		return account.ErrInvalidCode
	}

	if !bytes.Equal(storedHash, codeHash) {
		_, _ = tx.ExecContext(ctx, `UPDATE email_confirmation_codes SET attempts = attempts + 1 WHERE account_id = $1`, accountID)
		_ = tx.Commit()
		return account.ErrInvalidCode
	}

	_, err = tx.ExecContext(ctx, `DELETE FROM email_confirmation_codes WHERE account_id = $1`, accountID)
	if err != nil {
		return fmt.Errorf("postgres: delete code failed: %w", err)
	}

	if err := tx.Commit(); err != nil {
		return fmt.Errorf("postgres: commit tx failed: %w", err)
	}

	return nil
}
