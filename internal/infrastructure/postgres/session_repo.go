package postgres

import (
	"context"
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type SessionRepository struct {
	db *sql.DB
}

var _ session.Repository = (*SessionRepository)(nil)

func NewSessionRepository(db *sql.DB) *SessionRepository {
	return &SessionRepository{db: db}
}

func (r *SessionRepository) CreateSession(ctx context.Context, deviceID device.DeviceID, accountID account.AccountID) (session.Session, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return session.Session{}, fmt.Errorf("postgres: generate session id failed: %w", err)
	}
	sessID := session.SessionID("sess_" + hex.EncodeToString(b))

	query := `
		INSERT INTO sessions (id, account_id, device_id)
		VALUES ($1, $2, $3)
		RETURNING id, account_id, device_id, connection_id, created_at, last_active_at, revoked_at
	`
	var res session.Session
	var connectionID sql.NullString
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, string(sessID), accountID, deviceID).Scan(
		&res.ID,
		&res.AccountID,
		&res.DeviceID,
		&connectionID,
		&res.CreatedAt,
		&res.LastActiveAt,
		&revokedAt,
	)
	if err != nil {
		return session.Session{}, fmt.Errorf("postgres: create session failed: %w", err)
	}

	res.ConnectionID = connectionID.String
	if revokedAt.Valid {
		res.RevokedAt = &revokedAt.Time
	}

	return res, nil
}

func (r *SessionRepository) FindSession(ctx context.Context, id session.SessionID) (session.Session, error) {
	query := `
		SELECT id, account_id, device_id, connection_id, created_at, last_active_at, revoked_at
		FROM sessions
		WHERE id = $1
	`
	var res session.Session
	var connectionID sql.NullString
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, string(id)).Scan(
		&res.ID,
		&res.AccountID,
		&res.DeviceID,
		&connectionID,
		&res.CreatedAt,
		&res.LastActiveAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return session.Session{}, session.ErrSessionNotFound
		}
		return session.Session{}, fmt.Errorf("postgres: find session failed: %w", err)
	}

	res.ConnectionID = connectionID.String
	if revokedAt.Valid {
		res.RevokedAt = &revokedAt.Time
	}

	return res, nil
}

func (r *SessionRepository) DeleteSession(ctx context.Context, id session.SessionID) error {
	query := `
		DELETE FROM sessions
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, string(id))
	if err != nil {
		return fmt.Errorf("postgres: delete session failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) TouchLastActive(ctx context.Context, id session.SessionID) error {
	query := `
		UPDATE sessions
		SET last_active_at = now()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, string(id))
	if err != nil {
		return fmt.Errorf("postgres: touch session failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) ListActiveByAccount(ctx context.Context, accountID account.AccountID) ([]session.Session, error) {
	query := `
		SELECT id, account_id, device_id, connection_id, created_at, last_active_at, revoked_at
		FROM sessions
		WHERE account_id = $1 AND revoked_at IS NULL
	`
	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list sessions failed: %w", err)
	}
	defer rows.Close()

	var list []session.Session
	for rows.Next() {
		var res session.Session
		var connectionID sql.NullString
		var revokedAt sql.NullTime
		err := rows.Scan(
			&res.ID,
			&res.AccountID,
			&res.DeviceID,
			&connectionID,
			&res.CreatedAt,
			&res.LastActiveAt,
			&revokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan session failed: %w", err)
		}
		res.ConnectionID = connectionID.String
		if revokedAt.Valid {
			res.RevokedAt = &revokedAt.Time
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id session.SessionID) error {
	query := `
		UPDATE sessions
		SET revoked_at = now()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, string(id))
	if err != nil {
		return fmt.Errorf("postgres: revoke session failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) RevokeAllByAccount(ctx context.Context, accountID account.AccountID, exceptSessionID *session.SessionID) error {
	var err error
	if exceptSessionID != nil {
		query := `
			UPDATE sessions
			SET revoked_at = now()
			WHERE account_id = $1 AND id <> $2 AND revoked_at IS NULL
		`
		_, err = r.db.ExecContext(ctx, query, accountID, string(*exceptSessionID))
	} else {
		query := `
			UPDATE sessions
			SET revoked_at = now()
			WHERE account_id = $1 AND revoked_at IS NULL
		`
		_, err = r.db.ExecContext(ctx, query, accountID)
	}
	if err != nil {
		return fmt.Errorf("postgres: revoke all sessions failed: %w", err)
	}
	return nil
}

func (r *SessionRepository) RevokeInactiveOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	query := `
		UPDATE sessions
		SET revoked_at = now()
		FROM accounts
		WHERE sessions.account_id = accounts.id
		  AND sessions.revoked_at IS NULL
		  AND accounts.session_ttl_months IS NOT NULL
		  AND sessions.last_active_at < now() - (accounts.session_ttl_months * interval '1 month')
	`
	res, err := r.db.ExecContext(ctx, query)
	if err != nil {
		return 0, fmt.Errorf("postgres: revoke inactive sessions failed: %w", err)
	}
	affected, err := res.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("postgres: rows affected check failed: %w", err)
	}
	return int(affected), nil
}
