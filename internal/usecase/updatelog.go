package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/message"
	"github.com/airlance/api/internal/domain/updatelog"
)

type TxStore struct {
	Messages message.Repository
	Updates  updatelog.Repository
}

type UnitOfWork interface {
	Execute(ctx context.Context, fn func(ctx context.Context, s TxStore) error) error
}
