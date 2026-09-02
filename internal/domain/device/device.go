// Package device defines registered client devices, fingerprint hashing, and repository interfaces.
package device

import (
	"context"
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

// Repository defines storage operations for devices.
type Repository interface {
	Create(ctx context.Context, d *Device) error
	GetByID(ctx context.Context, id uuid.UUID) (*Device, error)
	GetByHash(ctx context.Context, hash []byte) (*Device, error)
	Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error
	UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error
	Revoke(ctx context.Context, id uuid.UUID) error
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Device, error)
}
