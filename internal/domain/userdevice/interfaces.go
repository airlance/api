package userdevice

import (
	"context"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
)

type Repository interface {
	GetByFingerprint(ctx context.Context, userID int32, fingerprint string) (*Device, error)
	Create(ctx context.Context, d *Device) error
	UpdateLastSeen(ctx context.Context, id int64, t time.Time) error
	GetOrCreate(ctx context.Context, userID int32, fingerprint string, cc clientcontext.ClientContext) (*Device, error)
}
