package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
	"github.com/airlance/api/internal/domain/userdevice"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"
)

type UserDeviceRepo struct {
	pool *pgxpool.Pool
}

func NewUserDeviceRepo(pool *pgxpool.Pool) *UserDeviceRepo {
	return &UserDeviceRepo{pool: pool}
}

func (r *UserDeviceRepo) GetByFingerprint(ctx context.Context, userID int32, fingerprint string) (*userdevice.Device, error) {
	const query = `
		SELECT id, user_id, fingerprint, COALESCE(device_name, ''), COALESCE(platform, ''), COALESCE(os, ''), first_seen_at, last_seen_at
		FROM user_devices WHERE user_id = $1 AND fingerprint = $2;`

	q := QueryFrom(ctx, r.pool)
	var d userdevice.Device
	var platformStr string
	err := q.QueryRow(ctx, query, userID, fingerprint).Scan(
		&d.ID, &d.UserID, &d.Fingerprint, &d.DeviceName, &platformStr, &d.OS, &d.FirstSeenAt, &d.LastSeenAt,
	)
	if err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, userdevice.ErrNotFound
		}
		return nil, fmt.Errorf("postgres: get device by fingerprint: %w", err)
	}
	d.Platform = clientcontext.Platform(platformStr)
	return &d, nil
}

func (r *UserDeviceRepo) Create(ctx context.Context, d *userdevice.Device) error {
	const query = `
		INSERT INTO user_devices (user_id, fingerprint, device_name, platform, os)
		VALUES ($1, $2, NULLIF($3, ''), NULLIF($4, ''), NULLIF($5, ''))
		RETURNING id, first_seen_at, last_seen_at;`

	q := QueryFrom(ctx, r.pool)
	err := q.QueryRow(ctx, query, d.UserID, d.Fingerprint, d.DeviceName, string(d.Platform), d.OS).
		Scan(&d.ID, &d.FirstSeenAt, &d.LastSeenAt)
	if err != nil {
		return fmt.Errorf("postgres: create device: %w", err)
	}
	return nil
}

func (r *UserDeviceRepo) UpdateLastSeen(ctx context.Context, id int64, t time.Time) error {
	const query = `UPDATE user_devices SET last_seen_at = $2 WHERE id = $1;`
	q := QueryFrom(ctx, r.pool)
	if _, err := q.Exec(ctx, query, id, t); err != nil {
		return fmt.Errorf("postgres: update device last seen: %w", err)
	}
	return nil
}

func (r *UserDeviceRepo) GetOrCreate(ctx context.Context, userID int32, fingerprint string, cc clientcontext.ClientContext) (*userdevice.Device, error) {
	existing, err := r.GetByFingerprint(ctx, userID, fingerprint)
	if err != nil && !errors.Is(err, userdevice.ErrNotFound) {
		return nil, err
	}
	if existing != nil {
		if err := r.UpdateLastSeen(ctx, existing.ID, time.Now()); err != nil {
			return nil, err
		}
		existing.LastSeenAt = time.Now()
		return existing, nil
	}

	d := &userdevice.Device{
		UserID:      userID,
		Fingerprint: fingerprint,
		Platform:    cc.Platform,
		OS:          cc.OS,
	}
	if err := r.Create(ctx, d); err != nil {
		return nil, err
	}
	return d, nil
}

var _ userdevice.Repository = (*UserDeviceRepo)(nil)
