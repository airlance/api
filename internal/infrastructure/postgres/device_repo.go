package postgres

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

type DeviceRepository struct {
	db *sql.DB
}

var _ device.Repository = (*DeviceRepository)(nil)

func NewDeviceRepository(db *sql.DB) *DeviceRepository {
	return &DeviceRepository{db: db}
}

func (r *DeviceRepository) CreateDevice(ctx context.Context, accountID account.AccountID, publicKey []byte) (device.Device, error) {
	query := `
		INSERT INTO devices (account_id, public_key)
		VALUES ($1, $2)
		RETURNING id, account_id, public_key, created_at, last_seen
	`
	var dev device.Device
	err := r.db.QueryRowContext(ctx, query, accountID, publicKey).Scan(
		&dev.ID,
		&dev.AccountID,
		&dev.PublicKey,
		&dev.CreatedAt,
		&dev.LastSeen,
	)
	if err != nil {
		return device.Device{}, fmt.Errorf("postgres: create device failed: %w", err)
	}
	return dev, nil
}

func (r *DeviceRepository) FindByPublicKey(ctx context.Context, publicKey []byte) (device.Device, error) {
	query := `
		SELECT id, account_id, public_key, created_at, last_seen
		FROM devices
		WHERE public_key = $1
	`
	var dev device.Device
	err := r.db.QueryRowContext(ctx, query, publicKey).Scan(
		&dev.ID,
		&dev.AccountID,
		&dev.PublicKey,
		&dev.CreatedAt,
		&dev.LastSeen,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return device.Device{}, device.ErrDeviceNotFound
		}
		return device.Device{}, fmt.Errorf("postgres: find device by public key failed: %w", err)
	}
	return dev, nil
}
