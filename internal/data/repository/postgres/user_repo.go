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

type UserRepository struct {
	pool *pgxpool.Pool
}

func NewUserRepository(pool *pgxpool.Pool) *UserRepository {
	return &UserRepository{pool: pool}
}

func (r *UserRepository) Create(ctx context.Context, u *user.User) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `INSERT INTO users (id, created_at) VALUES ($1, $2)`
	_, err := exec.Exec(ctx, query, u.ID, u.CreatedAt)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return user.ErrAlreadyExists
		}
		return fmt.Errorf("user_repo: create failed: %w", err)
	}
	return nil
}

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
