package device

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, d *Device) error
	GetByID(ctx context.Context, id uuid.UUID) (*Device, error)
	GetByHash(ctx context.Context, hash []byte) (*Device, error)
	Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error
	UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error
	Revoke(ctx context.Context, id uuid.UUID) error
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Device, error)
}
