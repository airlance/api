package tx

import (
	"context"
)

type TxManager interface {
	WithTx(ctx context.Context, fn func(txCtx context.Context) error) error
}
