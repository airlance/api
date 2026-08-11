package session

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

type Repository interface {
	CreateSession(ctx context.Context, deviceID device.DeviceID, accountID account.AccountID) (Session, error)
	FindSession(ctx context.Context, id SessionID) (Session, error)
	DeleteSession(ctx context.Context, id SessionID) error
}
