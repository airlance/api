package session

import (
	"context"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

type Repository interface {
	CreateSession(ctx context.Context, deviceID device.DeviceID, accountID account.AccountID) (Session, error)
	FindSession(ctx context.Context, id SessionID) (Session, error)
	DeleteSession(ctx context.Context, id SessionID) error
	TouchLastActive(ctx context.Context, id SessionID) error
	ListActiveByAccount(ctx context.Context, accountID account.AccountID) ([]Session, error)
	Revoke(ctx context.Context, id SessionID) error
	RevokeAllByAccount(ctx context.Context, accountID account.AccountID, exceptSessionID *SessionID) error
	RevokeInactiveOlderThan(ctx context.Context, cutoff time.Time) (int, error)
}
