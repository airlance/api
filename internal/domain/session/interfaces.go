package session

import (
	"context"
	"time"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, s *Session) error
	GetValid(ctx context.Context, tokenHash []byte) (*Session, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Session, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Session, error)
	Revoke(ctx context.Context, tokenHash []byte) error
	RevokeByID(ctx context.Context, id uuid.UUID) error
	RevokeAllForUser(ctx context.Context, userID uuid.UUID) error
	RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error
	CleanupExpired(ctx context.Context, before time.Time) (int64, error)
}
