package updatelog

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
)

type Repository interface {
	Append(ctx context.Context, accountID account.AccountID, kind UpdateKind, payload []byte) (Seq, error)
	ListSince(ctx context.Context, accountID account.AccountID, sinceSeq Seq, limit int) (updates []Update, currentSeq Seq, hasMore bool, err error)
	CurrentSeq(ctx context.Context, accountID account.AccountID) (Seq, error)
}
