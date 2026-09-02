package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/otp"
	"airlance.org/api/internal/infrastructure/database"
)

type OTPRepository struct {
	pool *pgxpool.Pool
}

func NewOTPRepository(pool *pgxpool.Pool) *OTPRepository {
	return &OTPRepository{pool: pool}
}

func (r *OTPRepository) Create(ctx context.Context, c *otp.Code) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO otp_codes (id, user_id, email, purpose, code_hash, key_id, attempts, max_attempts, expires_at, consumed_at, created_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11)
	`
	_, err := exec.Exec(ctx, query, c.ID, c.UserID, c.Email, string(c.Purpose), c.CodeHash, c.KeyID, c.Attempts, c.MaxAttempts, c.ExpiresAt, c.ConsumedAt, c.CreatedAt)
	if err != nil {
		return fmt.Errorf("otp_repo: create failed: %w", err)
	}
	return nil
}

func (r *OTPRepository) GetActiveByID(ctx context.Context, id uuid.UUID) (*otp.Code, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, user_id, email, purpose, code_hash, key_id, attempts, max_attempts, expires_at, consumed_at, created_at
		FROM otp_codes
		WHERE id = $1
	`
	row := exec.QueryRow(ctx, query, id)

	var c otp.Code
	var purposeStr string
	if err := row.Scan(&c.ID, &c.UserID, &c.Email, &purposeStr, &c.CodeHash, &c.KeyID, &c.Attempts, &c.MaxAttempts, &c.ExpiresAt, &c.ConsumedAt, &c.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, otp.ErrNotFound
		}
		return nil, fmt.Errorf("otp_repo: get active by id failed: %w", err)
	}
	c.Purpose = otp.Purpose(purposeStr)

	now := time.Now()
	if c.ConsumedAt != nil {
		return nil, otp.ErrNotFound
	}
	if !now.Before(c.ExpiresAt) {
		return nil, otp.ErrExpired
	}
	if c.Attempts >= c.MaxAttempts {
		return nil, otp.ErrTooManyAttempts
	}

	return &c, nil
}

func (r *OTPRepository) IncrementAttempts(ctx context.Context, id uuid.UUID) (int, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE otp_codes SET attempts = attempts + 1 WHERE id = $1 RETURNING attempts`
	row := exec.QueryRow(ctx, query, id)

	var attempts int
	if err := row.Scan(&attempts); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return 0, otp.ErrNotFound
		}
		return 0, fmt.Errorf("otp_repo: increment attempts failed: %w", err)
	}
	return attempts, nil
}

func (r *OTPRepository) ConsumeByID(ctx context.Context, id uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE otp_codes SET consumed_at = NOW() WHERE id = $1 AND consumed_at IS NULL`
	cmd, err := exec.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("otp_repo: consume by id failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return otp.ErrNotFound
	}
	return nil
}

func (r *OTPRepository) InvalidateActive(ctx context.Context, email string, purpose otp.Purpose) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE otp_codes SET consumed_at = NOW() WHERE email = $1 AND purpose = $2 AND consumed_at IS NULL`
	_, err := exec.Exec(ctx, query, email, string(purpose))
	if err != nil {
		return fmt.Errorf("otp_repo: invalidate active failed: %w", err)
	}
	return nil
}

func (r *OTPRepository) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `DELETE FROM otp_codes WHERE expires_at < $1`
	cmd, err := exec.Exec(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("otp_repo: cleanup expired failed: %w", err)
	}
	return cmd.RowsAffected(), nil
}
