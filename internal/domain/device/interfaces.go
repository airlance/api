package device

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
)

type Repository interface {
	CreateDevice(ctx context.Context, accountID account.AccountID, publicKey []byte) (Device, error)
	FindByPublicKey(ctx context.Context, publicKey []byte) (Device, error)
}
