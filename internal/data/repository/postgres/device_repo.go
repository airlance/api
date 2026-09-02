package postgres

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgxpool"

	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/infrastructure/database"
)

// DeviceRepository implements device.Repository for PostgreSQL.
type DeviceRepository struct {
	pool *pgxpool.Pool
}

// NewDeviceRepository constructs a DeviceRepository.
func NewDeviceRepository(pool *pgxpool.Pool) *DeviceRepository {
	return &DeviceRepository{pool: pool}
}

// Create registers a new client device.
func (r *DeviceRepository) Create(ctx context.Context, d *device.Device) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		INSERT INTO devices (id, user_id, device_identifier_hash, platform, created_at, last_seen_at, last_app_version, revoked_at)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
	`
	_, err := exec.Exec(ctx, query, d.ID, d.UserID, d.DeviceIdentifierHash, d.Platform, d.CreatedAt, d.LastSeenAt, d.LastAppVersion, d.RevokedAt)
	if err != nil {
		return fmt.Errorf("device_repo: create failed: %w", err)
	}
	return nil
}

// GetByID retrieves a device by ID.
func (r *DeviceRepository) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, user_id, device_identifier_hash, platform, created_at, last_seen_at, last_app_version, revoked_at
		FROM devices
		WHERE id = $1
	`
	row := exec.QueryRow(ctx, query, id)

	var d device.Device
	if err := row.Scan(&d.ID, &d.UserID, &d.DeviceIdentifierHash, &d.Platform, &d.CreatedAt, &d.LastSeenAt, &d.LastAppVersion, &d.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, device.ErrNotFound
		}
		return nil, fmt.Errorf("device_repo: get by id failed: %w", err)
	}
	return &d, nil
}

// GetByHash retrieves a device by its identifier HMAC hash.
func (r *DeviceRepository) GetByHash(ctx context.Context, hash []byte) (*device.Device, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, user_id, device_identifier_hash, platform, created_at, last_seen_at, last_app_version, revoked_at
		FROM devices
		WHERE device_identifier_hash = $1
	`
	row := exec.QueryRow(ctx, query, hash)

	var d device.Device
	if err := row.Scan(&d.ID, &d.UserID, &d.DeviceIdentifierHash, &d.Platform, &d.CreatedAt, &d.LastSeenAt, &d.LastAppVersion, &d.RevokedAt); err != nil {
		if errors.Is(err, pgx.ErrNoRows) {
			return nil, device.ErrNotFound
		}
		return nil, fmt.Errorf("device_repo: get by hash failed: %w", err)
	}
	return &d, nil
}

// Touch updates a device's last seen time and optional app version.
func (r *DeviceRepository) Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		UPDATE devices
		SET last_seen_at = $1, last_app_version = COALESCE($2, last_app_version)
		WHERE id = $3 AND revoked_at IS NULL
	`
	cmd, err := exec.Exec(ctx, query, lastSeen, appVersion, id)
	if err != nil {
		return fmt.Errorf("device_repo: touch failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return device.ErrNotFound
	}
	return nil
}

// UpdateHash updates the device identifier hash during key ring migration.
func (r *DeviceRepository) UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE devices SET device_identifier_hash = $1 WHERE id = $2`
	cmd, err := exec.Exec(ctx, query, newHash, id)
	if err != nil {
		return fmt.Errorf("device_repo: update hash failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return device.ErrNotFound
	}
	return nil
}

// Revoke marks a device as revoked.
func (r *DeviceRepository) Revoke(ctx context.Context, id uuid.UUID) error {
	exec := database.GetExecutor(ctx, r.pool)
	query := `UPDATE devices SET revoked_at = NOW() WHERE id = $1 AND revoked_at IS NULL`
	cmd, err := exec.Exec(ctx, query, id)
	if err != nil {
		return fmt.Errorf("device_repo: revoke failed: %w", err)
	}
	if cmd.RowsAffected() == 0 {
		return device.ErrNotFound
	}
	return nil
}

// ListByUserID returns all devices registered to a user.
func (r *DeviceRepository) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	exec := database.GetExecutor(ctx, r.pool)
	query := `
		SELECT id, user_id, device_identifier_hash, platform, created_at, last_seen_at, last_app_version, revoked_at
		FROM devices
		WHERE user_id = $1
		ORDER BY created_at ASC
	`
	rows, err := exec.Query(ctx, query, userID)
	if err != nil {
		return nil, fmt.Errorf("device_repo: list by user id failed: %w", err)
	}
	defer rows.Close()

	var res []*device.Device
	for rows.Next() {
		var d device.Device
		if err := rows.Scan(&d.ID, &d.UserID, &d.DeviceIdentifierHash, &d.Platform, &d.CreatedAt, &d.LastSeenAt, &d.LastAppVersion, &d.RevokedAt); err != nil {
			return nil, fmt.Errorf("device_repo: scan failed: %w", err)
		}
		res = append(res, &d)
	}
	return res, rows.Err()
}
