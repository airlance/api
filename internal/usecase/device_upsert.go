package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

type DeviceInfo struct {
	PublicKey   []byte
	Fingerprint string
	DeviceName  string
	Platform    string
	OSVersion   string
	AppVersion  string
}

func upsertDevice(ctx context.Context, devices device.Repository, accountID account.AccountID, info DeviceInfo) (dev device.Device, wasCreated bool, err error) {
	if info.Fingerprint != "" {
		if existing, err := devices.FindByFingerprint(ctx, accountID, info.Fingerprint); err == nil {
			_ = devices.TouchLastSeen(ctx, existing.ID)
			return existing, false, nil
		}
	}
	created, err := devices.CreateDevice(ctx, device.Device{
		AccountID:   accountID,
		PublicKey:   info.PublicKey,
		Fingerprint: info.Fingerprint,
		DeviceName:  info.DeviceName,
		Platform:    info.Platform,
		OSVersion:   info.OSVersion,
		AppVersion:  info.AppVersion,
	})
	return created, err == nil, err
}
