package postgres

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/clientcontext"
	"github.com/airlance/api/internal/domain/session"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type SessionRepo struct {
	pool *pgxpool.Pool
}

func NewSessionRepo(pool *pgxpool.Pool) *SessionRepo {
	return &SessionRepo{pool: pool}
}

func (r *SessionRepo) Create(ctx context.Context, s *session.Session) error {
	const query = `
		INSERT INTO sessions (auth_key_id, user_id, auth_identity_id, device_id, ip_address, user_agent, resume_secret_hash)
		VALUES ($1, $2, $3, $4, $5, $6, $7)
		RETURNING created_at, last_active_at;`

	q := QueryFrom(ctx, r.pool)

	err := q.QueryRow(ctx, query,
		int64(s.AuthKeyID), s.UserID, s.AuthIdentityID, s.DeviceID, s.IPAddress, s.UserAgent, s.ResumeSecretHash,
	).Scan(&s.CreatedAt, &s.LastActiveAt)
	if err != nil {
		return fmt.Errorf("postgres: create session: %w", err)
	}
	return nil
}

func (r *SessionRepo) GetActive(ctx context.Context, authKeyID uint64) (*session.Session, error) {
	const query = `
		SELECT auth_key_id, user_id, auth_identity_id, device_id, COALESCE(ip_address::text, ''), user_agent,
		       resume_secret_hash, last_seen_seq, created_at, last_active_at, revoked_at, COALESCE(revoked_reason, '')
		FROM sessions WHERE auth_key_id = $1 AND revoked_at IS NULL;`

	return r.scanOne(ctx, query, int64(authKeyID))
}

func (r *SessionRepo) GetAny(ctx context.Context, authKeyID uint64) (*session.Session, error) {
	const query = `
		SELECT auth_key_id, user_id, auth_identity_id, device_id, COALESCE(ip_address::text, ''), user_agent,
		       resume_secret_hash, last_seen_seq, created_at, last_active_at, revoked_at, COALESCE(revoked_reason, '')
		FROM sessions WHERE auth_key_id = $1;`

	return r.scanOne(ctx, query, int64(authKeyID))
}

func (r *SessionRepo) scanOne(ctx context.Context, query string, authKeyID int64) (*session.Session, error) {
	q := QueryFrom(ctx, r.pool)

	var s session.Session
	var rawAuthKeyID int64
	var revokedReason string
	err := q.QueryRow(ctx, query, authKeyID).Scan(
		&rawAuthKeyID, &s.UserID, &s.AuthIdentityID, &s.DeviceID, &s.IPAddress, &s.UserAgent,
		&s.ResumeSecretHash, &s.LastSeenSeq, &s.CreatedAt, &s.LastActiveAt, &s.RevokedAt, &revokedReason,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, session.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get session: %w", err)
	}
	s.AuthKeyID = uint64(rawAuthKeyID)
	s.RevokedReason = session.RevokeReason(revokedReason)
	return &s, nil
}

func (r *SessionRepo) ListActiveByUserID(ctx context.Context, userID int32) ([]*session.SessionView, error) {
	const query = `
		SELECT s.auth_key_id, s.user_id, s.auth_identity_id, s.device_id, COALESCE(s.ip_address::text, ''),
		       s.user_agent, s.resume_secret_hash, s.last_seen_seq, s.created_at, s.last_active_at,
		       s.revoked_at, COALESCE(s.revoked_reason, ''),
		       COALESCE(d.device_name, ''), COALESCE(d.platform, ''), COALESCE(d.os, '')
		FROM sessions s
		LEFT JOIN user_devices d ON d.id = s.device_id
		WHERE s.user_id = $1 AND s.revoked_at IS NULL
		ORDER BY s.last_active_at DESC;`

	q := QueryFrom(ctx, r.pool)
	rows, err := q.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list active sessions: %w", err)
	}
	defer rows.Close()

	var views []*session.SessionView
	for rows.Next() {
		var v session.SessionView
		var rawAuthKeyID int64
		var revokedReason, platformStr string
		if err := rows.Scan(
			&rawAuthKeyID, &v.UserID, &v.AuthIdentityID, &v.DeviceID, &v.IPAddress,
			&v.UserAgent, &v.ResumeSecretHash, &v.LastSeenSeq, &v.CreatedAt, &v.LastActiveAt,
			&v.RevokedAt, &revokedReason, &v.DeviceName, &platformStr, &v.OS,
		); err != nil {
			return nil, fmt.Errorf("postgres: scan session view: %w", err)
		}
		v.AuthKeyID = uint64(rawAuthKeyID)
		v.RevokedReason = session.RevokeReason(revokedReason)
		v.Platform = clientcontext.Platform(platformStr)
		views = append(views, &v)
	}
	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("postgres: iterate session views: %w", err)
	}
	return views, nil
}

func (r *SessionRepo) UpdateLastSeenSeq(ctx context.Context, authKeyID uint64, seq uint64) error {
	const query = `
		UPDATE sessions SET last_seen_seq = $2, last_active_at = now()
		WHERE auth_key_id = $1 AND revoked_at IS NULL;`

	q := QueryFrom(ctx, r.pool)
	tag, err := q.Exec(ctx, query, int64(authKeyID), int64(seq))
	if err != nil {
		return fmt.Errorf("postgres: update last seen seq: %w", err)
	}
	if tag.RowsAffected() == 0 {
		return session.ErrNotFound
	}
	return nil
}

func (r *SessionRepo) Revoke(ctx context.Context, authKeyID uint64, reason session.RevokeReason) error {
	const query = `
		UPDATE sessions SET revoked_at = now(), revoked_reason = $2
		WHERE auth_key_id = $1 AND revoked_at IS NULL;`

	q := QueryFrom(ctx, r.pool)
	if _, err := q.Exec(ctx, query, int64(authKeyID), string(reason)); err != nil {
		return fmt.Errorf("postgres: revoke session: %w", err)
	}
	return nil
}

func (r *SessionRepo) RevokeAllByUserID(ctx context.Context, userID int32, reason session.RevokeReason) error {
	const query = `
		UPDATE sessions SET revoked_at = now(), revoked_reason = $2
		WHERE user_id = $1 AND revoked_at IS NULL;`

	q := QueryFrom(ctx, r.pool)
	if _, err := q.Exec(ctx, query, userID, string(reason)); err != nil {
		return fmt.Errorf("postgres: revoke all sessions for user: %w", err)
	}
	return nil
}

var _ session.Repository = (*SessionRepo)(nil)
