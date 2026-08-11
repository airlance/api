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

func (r *DeviceRepository) CreateDevice(ctx context.Context, dev device.Device) (device.Device, error) {
	query := `
		INSERT INTO devices (account_id, public_key, fingerprint, device_name, platform, os_version, app_version, push_token)
		VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
		RETURNING id, account_id, public_key, fingerprint, device_name, platform, os_version, app_version, push_token, first_seen_at, last_seen_at, revoked_at
	`
	var res device.Device
	var fingerprint, deviceName, platform, osVersion, appVersion, pushToken sql.NullString
	if dev.Fingerprint != "" {
		fingerprint = sql.NullString{String: dev.Fingerprint, Valid: true}
	}
	if dev.DeviceName != "" {
		deviceName = sql.NullString{String: dev.DeviceName, Valid: true}
	}
	if dev.Platform != "" {
		platform = sql.NullString{String: dev.Platform, Valid: true}
	}
	if dev.OSVersion != "" {
		osVersion = sql.NullString{String: dev.OSVersion, Valid: true}
	}
	if dev.AppVersion != "" {
		appVersion = sql.NullString{String: dev.AppVersion, Valid: true}
	}
	if dev.PushToken != "" {
		pushToken = sql.NullString{String: dev.PushToken, Valid: true}
	}

	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query,
		dev.AccountID,
		dev.PublicKey,
		fingerprint,
		deviceName,
		platform,
		osVersion,
		appVersion,
		pushToken,
	).Scan(
		&res.ID,
		&res.AccountID,
		&res.PublicKey,
		&fingerprint,
		&deviceName,
		&platform,
		&osVersion,
		&appVersion,
		&pushToken,
		&res.FirstSeenAt,
		&res.LastSeenAt,
		&revokedAt,
	)
	if err != nil {
		return device.Device{}, fmt.Errorf("postgres: create device failed: %w", err)
	}

	res.Fingerprint = fingerprint.String
	res.DeviceName = deviceName.String
	res.Platform = platform.String
	res.OSVersion = osVersion.String
	res.AppVersion = appVersion.String
	res.PushToken = pushToken.String
	if revokedAt.Valid {
		res.RevokedAt = &revokedAt.Time
	}

	return res, nil
}

func (r *DeviceRepository) FindByPublicKey(ctx context.Context, publicKey []byte) (device.Device, error) {
	query := `
		SELECT id, account_id, public_key, fingerprint, device_name, platform, os_version, app_version, push_token, first_seen_at, last_seen_at, revoked_at
		FROM devices
		WHERE public_key = $1
	`
	var res device.Device
	var fingerprint, deviceName, platform, osVersion, appVersion, pushToken sql.NullString
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, publicKey).Scan(
		&res.ID,
		&res.AccountID,
		&res.PublicKey,
		&fingerprint,
		&deviceName,
		&platform,
		&osVersion,
		&appVersion,
		&pushToken,
		&res.FirstSeenAt,
		&res.LastSeenAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return device.Device{}, device.ErrDeviceNotFound
		}
		return device.Device{}, fmt.Errorf("postgres: find device by public key failed: %w", err)
	}

	res.Fingerprint = fingerprint.String
	res.DeviceName = deviceName.String
	res.Platform = platform.String
	res.OSVersion = osVersion.String
	res.AppVersion = appVersion.String
	res.PushToken = pushToken.String
	if revokedAt.Valid {
		res.RevokedAt = &revokedAt.Time
	}

	return res, nil
}

func (r *DeviceRepository) FindByFingerprint(ctx context.Context, accountID account.AccountID, fingerprint string) (device.Device, error) {
	query := `
		SELECT id, account_id, public_key, fingerprint, device_name, platform, os_version, app_version, push_token, first_seen_at, last_seen_at, revoked_at
		FROM devices
		WHERE account_id = $1 AND fingerprint = $2
	`
	var res device.Device
	var fpStr, deviceName, platform, osVersion, appVersion, pushToken sql.NullString
	var revokedAt sql.NullTime

	err := r.db.QueryRowContext(ctx, query, accountID, fingerprint).Scan(
		&res.ID,
		&res.AccountID,
		&res.PublicKey,
		&fpStr,
		&deviceName,
		&platform,
		&osVersion,
		&appVersion,
		&pushToken,
		&res.FirstSeenAt,
		&res.LastSeenAt,
		&revokedAt,
	)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return device.Device{}, device.ErrDeviceNotFound
		}
		return device.Device{}, fmt.Errorf("postgres: find device by fingerprint failed: %w", err)
	}

	res.Fingerprint = fpStr.String
	res.DeviceName = deviceName.String
	res.Platform = platform.String
	res.OSVersion = osVersion.String
	res.AppVersion = appVersion.String
	res.PushToken = pushToken.String
	if revokedAt.Valid {
		res.RevokedAt = &revokedAt.Time
	}

	return res, nil
}

func (r *DeviceRepository) TouchLastSeen(ctx context.Context, id device.DeviceID) error {
	query := `
		UPDATE devices
		SET last_seen_at = now()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("postgres: touch device last seen failed: %w", err)
	}
	return nil
}

func (r *DeviceRepository) ListByAccount(ctx context.Context, accountID account.AccountID) ([]device.Device, error) {
	query := `
		SELECT id, account_id, public_key, fingerprint, device_name, platform, os_version, app_version, push_token, first_seen_at, last_seen_at, revoked_at
		FROM devices
		WHERE account_id = $1
	`
	rows, err := r.db.QueryContext(ctx, query, accountID)
	if err != nil {
		return nil, fmt.Errorf("postgres: list devices failed: %w", err)
	}
	defer rows.Close()

	var list []device.Device
	for rows.Next() {
		var res device.Device
		var fingerprint, deviceName, platform, osVersion, appVersion, pushToken sql.NullString
		var revokedAt sql.NullTime
		err := rows.Scan(
			&res.ID,
			&res.AccountID,
			&res.PublicKey,
			&fingerprint,
			&deviceName,
			&platform,
			&osVersion,
			&appVersion,
			&pushToken,
			&res.FirstSeenAt,
			&res.LastSeenAt,
			&revokedAt,
		)
		if err != nil {
			return nil, fmt.Errorf("postgres: scan device failed: %w", err)
		}
		res.Fingerprint = fingerprint.String
		res.DeviceName = deviceName.String
		res.Platform = platform.String
		res.OSVersion = osVersion.String
		res.AppVersion = appVersion.String
		res.PushToken = pushToken.String
		if revokedAt.Valid {
			res.RevokedAt = &revokedAt.Time
		}
		list = append(list, res)
	}
	return list, nil
}

func (r *DeviceRepository) Revoke(ctx context.Context, id device.DeviceID) error {
	query := `
		UPDATE devices
		SET revoked_at = now()
		WHERE id = $1
	`
	_, err := r.db.ExecContext(ctx, query, id)
	if err != nil {
		return fmt.Errorf("postgres: revoke device failed: %w", err)
	}
	return nil
}
