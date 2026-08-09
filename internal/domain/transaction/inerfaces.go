package transaction

import "context"

type TxManager interface {
	WithinTx(ctx context.Context, fn func(ctx context.Context) error) error
}
