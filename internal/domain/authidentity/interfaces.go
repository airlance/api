package authidentity

import (
	"context"
	"time"
)

type Repository interface {
	GetByProviderIdentifier(ctx context.Context, provider Provider, identifier string) (*Identity, error)
	GetAnyByUserID(ctx context.Context, userID int32) (*Identity, error)
	Create(ctx context.Context, i *Identity) error
	UpdateLastUsed(ctx context.Context, id int64, t time.Time) error
}
