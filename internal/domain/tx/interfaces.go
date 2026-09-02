package tx

import (
	"context"
)

// TxManager manages atomic transactional execution boundaries across domain repositories.
type TxManager interface {
	WithTx(ctx context.Context, fn func(txCtx context.Context) error) error
}
