package session

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
)

var ErrSessionNotFound = errors.New("session not found")

type SessionID string

type Session struct {
	ID           SessionID
	DeviceID     device.DeviceID
	AccountID    account.AccountID
	ConnectionID string
	CreatedAt    time.Time
}
