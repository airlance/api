// Package postgres provides PostgreSQL implementations of domain repositories using pgx.
package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/user"
	"airlance.org/api/internal/infrastructure/database"
)

// UserRepository implements user.Repository for PostgreSQL.
type UserRepository struct {
	pool *pgxpool.Pool
}

// NewUserRepository constructs a UserRepository.
func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

// Create inserts a new user record.
func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `INSERT INTO users (id, created_at) VALUES ($1, $2)`
	_, err := exec.Exec(ctx, query, u.ID, u.CreatedAt)
	if err != nil {
		var pgErr *pgconn.PgError
		if errors.As(err, &pgErr) && pgErr.Code == "23505" {
			return user.ErrAlreadyExists
		}
		return fmt.Errorf("user_repo: create failed: %w", err)
	}
	return nil
}

// GetByID retrieves a user by ID.
func (r *UserRepository) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `SELECT id, created_at FROM users WHERE id = $1`
	row := exec.QueryRow(ctx, query, id)

	var u user.User
	if err := row.Scan(&u.ID, &u.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, fmt.Errorf("user_repo: get by id failed: %w", err)
	}
	return &u, nil
}
