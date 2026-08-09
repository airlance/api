package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type AuthIdentityRepo struct {
	pool *pgxpool.Pool
}

func NewAuthIdentityRepo(pool *pgxpool.Pool) *AuthIdentityRepo {
	return &AuthIdentityRepo{pool: pool}
}

func (r *AuthIdentityRepo) GetByProviderIdentifier(ctx context.Context, provider authidentity.Provider, identifier string) (*authidentity.Identity, error) {
	const query = `
		SELECT id, user_id, provider, identifier, created_at, last_used_at
		FROM auth_identities WHERE provider = $1 AND identifier = $2;`

	q := QueryFrom(ctx, r.pool)
	var i authidentity.Identity
	var providerStr string
	err := q.QueryRow(ctx, query, string(provider), identifier).Scan(
		&i.ID, &i.UserID, &providerStr, &i.Identifier, &i.CreatedAt, &i.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, authidentity.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get identity: %w", err)
	}
	i.Provider = authidentity.Provider(providerStr)
	return &i, nil
}

func (r *AuthIdentityRepo) GetAnyByUserID(ctx context.Context, userID int32) (*authidentity.Identity, error) {
	const query = `
		SELECT id, user_id, provider, identifier, created_at, last_used_at
		FROM auth_identities WHERE user_id = $1
		ORDER BY last_used_at DESC
		LIMIT 1;`

	q := QueryFrom(ctx, r.pool)
	var i authidentity.Identity
	var providerStr string
	err := q.QueryRow(ctx, query, userID).Scan(
		&i.ID, &i.UserID, &providerStr, &i.Identifier, &i.CreatedAt, &i.LastUsedAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, authidentity.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get any identity by user: %w", err)
	}
	i.Provider = authidentity.Provider(providerStr)
	return &i, nil
}

func (r *AuthIdentityRepo) Create(ctx context.Context, i *authidentity.Identity) error {
	const query = `
		INSERT INTO auth_identities (user_id, provider, identifier)
		VALUES ($1, $2, $3)
		RETURNING id, created_at, last_used_at;`

	q := QueryFrom(ctx, r.pool)
	err := q.QueryRow(ctx, query, i.UserID, string(i.Provider), i.Identifier).
		Scan(&i.ID, &i.CreatedAt, &i.LastUsedAt)
	if err != nil {
		return fmt.Errorf("postgres: create identity: %w", err)
	}
	return nil
}

func (r *AuthIdentityRepo) UpdateLastUsed(ctx context.Context, id int64, t time.Time) error {
	const query = `UPDATE auth_identities SET last_used_at = $2 WHERE id = $1;`
	q := QueryFrom(ctx, r.pool)
	if _, err := q.Exec(ctx, query, id, t); err != nil {
		return fmt.Errorf("postgres: update identity last used: %w", err)
	}
	return nil
}

var _ authidentity.Repository = (*AuthIdentityRepo)(nil)
