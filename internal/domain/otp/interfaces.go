package otp

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, c *Code) error
	GetActiveByID(ctx context.Context, id uuid.UUID) (*Code, error)
	IncrementAttempts(ctx context.Context, id uuid.UUID) (attempts int, err error)
	ConsumeByID(ctx context.Context, id uuid.UUID) error
	InvalidateActive(ctx context.Context, email string, purpose Purpose) error
	CleanupExpired(ctx context.Context, before time.Time) (int64, error)
}
