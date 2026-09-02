package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/infrastructure/database"
)

type IdentityRepository struct {
	pool *pgxpool.Pool
}

func NewIdentityRepository(pool *pgxpool.Pool) *IdentityRepository {
	return &IdentityRepository{pool: pool}
}

func (r *IdentityRepository) Create(ctx context.Context, ident *identity.Identity) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO identities (id, user_id, kind, identifier, verified, created_at)
		VALUES ($1, $2, $3, $4, $5, $6)
	`
	_, err := exec.Exec(ctx, query, ident.ID, ident.UserID, string(ident.Kind), ident.Identifier, ident.Verified, ident.CreatedAt)
	if err != nil {
		if pgErr, ok := errors.AsType[*pgconn.PgError](err); ok && pgErr.Code == "23505" {
			return identity.ErrAlreadyExists
		}
		return fmt.Errorf("identity_repo: create failed: %w", err)
	}
	return nil
}

func (r *IdentityRepository) GetByID(ctx context.Context, id uuid.UUID) (*identity.Identity, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `SELECT id, user_id, kind, identifier, verified, created_at FROM identities WHERE id = $1`
	row := exec.QueryRow(ctx, query, id)

	var ident identity.Identity
	var kindStr string
	if err := row.Scan(&ident.ID, &ident.UserID, &kindStr, &ident.Identifier, &ident.Verified, &ident.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrNotFound
		}
		return nil, fmt.Errorf("identity_repo: get by id failed: %w", err)
	}
	ident.Kind = identity.Kind(kindStr)
	return &ident, nil
}

func (r *IdentityRepository) GetByKindAndIdentifier(ctx context.Context, kind identity.Kind, identifier string) (*identity.Identity, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `SELECT id, user_id, kind, identifier, verified, created_at FROM identities WHERE kind = $1 AND identifier = $2`
	row := exec.QueryRow(ctx, query, string(kind), identifier)

	var ident identity.Identity
	var kindStr string
	if err := row.Scan(&ident.ID, &ident.UserID, &kindStr, &ident.Identifier, &ident.Verified, &ident.CreatedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, identity.ErrNotFound
		}
		return nil, fmt.Errorf("identity_repo: get by kind and identifier failed: %w", err)
	}
	ident.Kind = identity.Kind(kindStr)
	return &ident, nil
}

func (r *IdentityRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*identity.Identity, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `SELECT id, user_id, kind, identifier, verified, created_at FROM identities WHERE user_id = $1 ORDER BY created_at ASC`
	rows, err := exec.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("identity_repo: list by user id failed: %w", err)
	}
	defer rows.Close()

	var res []*identity.Identity
	for rows.Next() {
		var ident identity.Identity
		var kindStr string
		if err := rows.Scan(&ident.ID, &ident.UserID, &kindStr, &ident.Identifier, &ident.Verified, &ident.CreatedAt); err != nil {
			return nil, fmt.Errorf("identity_repo: scan failed: %w", err)
		}
		ident.Kind = identity.Kind(kindStr)
		res = append(res, &ident)
	}
	return res, rows.Err()
}

func (r *IdentityRepository) MarkVerified(ctx context.Context, id uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE identities SET verified = TRUE WHERE id = $1`
	cmd, err := exec.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("identity_repo: mark verified failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return identity.ErrNotFound
	}
	return nil
}
