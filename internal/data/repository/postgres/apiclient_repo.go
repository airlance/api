package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/infrastructure/database"
)

type APIClientRepository struct {
	pool *pgxpool.Pool
}

func NewAPIClientRepository(pool *pgxpool.Pool) *APIClientRepository {
	return &APIClientRepository{pool: pool}
}

func (r *APIClientRepository) Create(ctx context.Context, client *apiclient.APIClient) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO api_clients (id, user_id, tier_id, name, secret_hash, created_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
	`
	_, err := exec.Exec(ctx, query, client.ID, client.UserID, client.TierID, client.Name, client.SecretHash, client.CreatedAt, client.RevokedAt)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return apiclient.ErrDuplicateName
		}
		return fmt.Errorf("apiclient_repo: create failed: %w", err)
	}
	return nil
}

func (r *APIClientRepository) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.APIClient, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, user_id, tier_id, name, secret_hash, created_at, revoked_at
		FROM api_clients
		WHERE id = $1
	`
	row := exec.QueryRow(ctx, query, id)

	var c apiclient.APIClient
	if err := row.Scan(&c.ID, &c.UserID, &c.TierID, &c.Name, &c.SecretHash, &c.CreatedAt, &c.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiclient.ErrClientNotFound
		}
		return nil, fmt.Errorf("apiclient_repo: get by id failed: %w", err)
	}
	return &c, nil
}

func (r *APIClientRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*apiclient.APIClient, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, user_id, tier_id, name, secret_hash, created_at, revoked_at
		FROM api_clients
		WHERE user_id = $1
		ORDER BY created_at ASC
	`
	rows, err := exec.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("apiclient_repo: list by user id failed: %w", err)
	}
	defer rows.Close()

	var res []*apiclient.APIClient
	for rows.Next() {
		var c apiclient.APIClient
		if err := rows.Scan(&c.ID, &c.UserID, &c.TierID, &c.Name, &c.SecretHash, &c.CreatedAt, &c.RevokedAt); err != nil {
			return nil, fmt.Errorf("apiclient_repo: scan failed: %w", err)
		}
		res = append(res, &c)
	}
	return res, rows.Err()
}

func (r *APIClientRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE api_clients SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`
	cmd, err := exec.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("apiclient_repo: revoke failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return apiclient.ErrClientNotFound
	}
	return nil
}

type RateLimitTierRepository struct {
	pool *pgxpool.Pool
}

func NewRateLimitTierRepository(pool *pgxpool.Pool) *RateLimitTierRepository {
	return &RateLimitTierRepository{pool: pool}
}

func (r *RateLimitTierRepository) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.RateLimitTier, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, name, requests_per_minute, requests_per_day, created_at
		FROM rate_limit_tiers
		WHERE id = $1
	`
	row := exec.QueryRow(ctx, query, id)

	var t apiclient.RateLimitTier
	if err := row.Scan(&t.ID, &t.Name, &t.RequestsPerMinute, &t.RequestsPerDay, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiclient.ErrTierNotFound
		}
		return nil, fmt.Errorf("tier_repo: get by id failed: %w", err)
	}
	return &t, nil
}

func (r *RateLimitTierRepository) GetByName(ctx context.Context, name string) (*apiclient.RateLimitTier, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, name, requests_per_minute, requests_per_day, created_at
		FROM rate_limit_tiers
		WHERE name = $1
	`
	row := exec.QueryRow(ctx, query, name)

	var t apiclient.RateLimitTier
	if err := row.Scan(&t.ID, &t.Name, &t.RequestsPerMinute, &t.RequestsPerDay, &t.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, apiclient.ErrTierNotFound
		}
		return nil, fmt.Errorf("tier_repo: get by name failed: %w", err)
	}
	return &t, nil
}
