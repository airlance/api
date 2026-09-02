package apiclient

import (
	"context"

	"github.com/google/uuid"
)

type Repository interface {
	Create(ctx context.Context, client *APIClient) error
	GetByID(ctx context.Context, id uuid.UUID) (*APIClient, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*APIClient, error)
	Revoke(ctx context.Context, id uuid.UUID) error
}

type TierRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*RateLimitTier, error)
	GetByName(ctx context.Context, name string) (*RateLimitTier, error)
}
