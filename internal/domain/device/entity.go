package device

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound = errors.New("device: not found")
	ErrRevoked  = errors.New("device: revoked")
)

type Device struct {
	ID                   uuid.UUID
	UserID               uuid.UUID
	DeviceIdentifierHash []byte
	Platform             string
	CreatedAt            time.Time
	LastSeenAt           time.Time
	LastAppVersion       *string
	RevokedAt            *time.Time
}

func (d *Device) IsValid() bool {
	return d.RevokedAt == nil
}
