package device

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/account"
)

var ErrDeviceNotFound = errors.New("device not found")

type DeviceID uint64

type Device struct {
	ID        DeviceID
	AccountID account.AccountID
	PublicKey []byte
	CreatedAt time.Time
	LastSeen  time.Time
}
