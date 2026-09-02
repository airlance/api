package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/infrastructure/database"
)

type SessionRepository struct {
	pool *pgxpool.Pool
}

func NewSessionRepository(pool *pgxpool.Pool) *SessionRepository {
	return &SessionRepository{pool: pool}
}

func (r *SessionRepository) Create(ctx context.Context, s *session.Session) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO sessions (id, token_hash, user_id, identity_id, device_id, created_at, expires_at, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := exec.Exec(ctx, query, s.ID, s.TokenHash, s.UserID, s.IdentityID, s.DeviceID, s.CreatedAt, s.ExpiresAt, s.RevokedAt)
	if err != nil {
		return fmt.Errorf("session_repo: create failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, token_hash, user_id, identity_id, device_id, created_at, expires_at, revoked_at
		FROM sessions
		WHERE token_hash = $1
	`
	row := exec.QueryRow(ctx, query, tokenHash)

	var s session.Session
	if err := row.Scan(&s.ID, &s.TokenHash, &s.UserID, &s.IdentityID, &s.DeviceID, &s.CreatedAt, &s.ExpiresAt, &s.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, session.ErrNotFound
		}
		return nil, fmt.Errorf("session_repo: get valid failed: %w", err)
	}

	if s.RevokedAt != nil {
		return nil, session.ErrRevoked
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, session.ErrExpired
	}

	return &s, nil
}

func (r *SessionRepository) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, token_hash, user_id, identity_id, device_id, created_at, expires_at, revoked_at
		FROM sessions
		WHERE id = $1
	`
	row := exec.QueryRow(ctx, query, id)

	var s session.Session
	if err := row.Scan(&s.ID, &s.TokenHash, &s.UserID, &s.IdentityID, &s.DeviceID, &s.CreatedAt, &s.ExpiresAt, &s.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, session.ErrNotFound
		}
		return nil, fmt.Errorf("session_repo: get by id failed: %w", err)
	}
	return &s, nil
}

func (r *SessionRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT s.id, s.token_hash, s.user_id, s.identity_id, s.device_id, COALESCE(d.platform, ''), s.created_at, s.expires_at, s.revoked_at
		FROM sessions s
		LEFT JOIN devices d ON s.device_id = d.id
		WHERE s.user_id = $1 AND s.revoked_at IS NULL AND s.expires_at > NOW()
		ORDER BY s.created_at DESC
	`
	rows, err := exec.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("session_repo: list by user id query failed: %w", err)
	}
	defer rows.Close()

	var sessions []*session.Session
	for rows.Next() {
		var s session.Session
		if err := rows.Scan(&s.ID, &s.TokenHash, &s.UserID, &s.IdentityID, &s.DeviceID, &s.Platform, &s.CreatedAt, &s.ExpiresAt, &s.RevokedAt); err != nil {
			return nil, fmt.Errorf("session_repo: list by user id scan failed: %w", err)
		}
		sessions = append(sessions, &s)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("session_repo: list by user id rows error: %w", err)
	}
	return sessions, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, tokenHash []byte) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE sessions SET revoked_at = NOW() WHERE token_hash = $1 AND revoked_at IS NULL`
	cmd, err := exec.Exec(ctx, query, tokenHash)
	if err != nil {
		return fmt.Errorf("session_repo: revoke failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return session.ErrNotFound
	}
	return nil
}

func (r *SessionRepository) RevokeByID(ctx context.Context, id uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE sessions SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`
	cmd, err := exec.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("session_repo: revoke by id failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return session.ErrNotFound
	}
	return nil
}

func (r *SessionRepository) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE sessions SET revoked_at = NOW() WHERE user_id = $1 AND revoked_at IS NULL`
	_, err := exec.Exec(ctx, query, userID)
	if err != nil {
		return fmt.Errorf("session_repo: revoke all for user failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE sessions SET revoked_at = NOW() WHERE device_id = $1 AND revoked_at IS NULL`
	_, err := exec.Exec(ctx, query, deviceID)
	if err != nil {
		return fmt.Errorf("session_repo: revoke all for device failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `DELETE FROM sessions WHERE expires_at < $1`
	cmd, err := exec.Exec(ctx, query, before)
	if err != nil {
		return 0, fmt.Errorf("session_repo: cleanup expired failed: %w", err)
	}
	return cmd.RowsAffected(), nil
}
