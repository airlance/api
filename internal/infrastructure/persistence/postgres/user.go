package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/user"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

const userColumns = `id, email, full_name, avatar_key, created_at, deactivated_at`

type UserRepo struct {
	pool *pgxpool.Pool
}

func NewUserRepo(pool *pgxpool.Pool) *UserRepo {
	return &UserRepo{pool: pool}
}

func scanUser(row pgx.Row) (*user.User, error) {
	var u user.User
	if err := row.Scan(&u.ID, &u.Email, &u.FullName, &u.AvatarKey, &u.CreatedAt, &u.DeactivatedAt); err != nil {
		return nil, err
	}
	return &u, nil
}

func (r *UserRepo) GetByID(ctx context.Context, id int32) (*user.User, error) {
	query := fmt.Sprintf(`SELECT %s FROM users WHERE id = $1;`, userColumns)

	q := QueryFrom(ctx, r.pool)
	u, err := scanUser(q.QueryRow(ctx, query, id))
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, user.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get user by id: %w", err)
	}
	return u, nil
}

func (r *UserRepo) GetOrCreateByEmail(ctx context.Context, email string, fullName string) (*user.User, error) {
	query := fmt.Sprintf(`
		INSERT INTO users (email, full_name) VALUES ($1, NULLIF($2, ''))
		ON CONFLICT (email) DO UPDATE SET email = EXCLUDED.email
		RETURNING %s;`, userColumns)

	q := QueryFrom(ctx, r.pool)
	u, err := scanUser(q.QueryRow(ctx, query, email, fullName))
	if err != nil {
		return nil, fmt.Errorf("postgres: get or create user by email: %w", err)
	}
	return u, nil
}

var _ user.Repository = (*UserRepo)(nil)
