package device

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound is returned when a device cannot be found.
	ErrNotFound = errors.New("device: not found")
	// ErrRevoked is returned when a device has been revoked.
	ErrRevoked = errors.New("device: revoked")
)

// Device represents a physical device associated with a user account.
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

// IsValid checks if the device is not revoked.
func (d *Device) IsValid() bool {
	return d.RevokedAt == nil
}
