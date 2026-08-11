package authidentity

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
)

type Repository interface {
	Create(ctx context.Context, identity AuthIdentity) (AuthIdentity, error)
	FindByProviderUserID(ctx context.Context, provider Provider, providerUserID string) (AuthIdentity, error)
	FindByAccountAndProvider(ctx context.Context, accountID account.AccountID, provider Provider) (AuthIdentity, error)
	ListByAccount(ctx context.Context, accountID account.AccountID) ([]AuthIdentity, error)
}
