package device

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
)

type Repository interface {
	CreateDevice(ctx context.Context, dev Device) (Device, error)
	FindByPublicKey(ctx context.Context, publicKey []byte) (Device, error)
	FindByFingerprint(ctx context.Context, accountID account.AccountID, fingerprint string) (Device, error)
	TouchLastSeen(ctx context.Context, id DeviceID) error
	ListByAccount(ctx context.Context, accountID account.AccountID) ([]Device, error)
	Revoke(ctx context.Context, id DeviceID) error
}

type NewDeviceNotifier interface {
	NotifyNewDevice(ctx context.Context, toEmail string, dev Device) error
}
