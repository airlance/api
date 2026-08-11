package updatelog

import (
	"time"

	"github.com/airlance/api/internal/domain/account"
)

type UpdateKind uint8

const (
	KindMessage UpdateKind = 1
)

type Seq int64

type Update struct {
	AccountID account.AccountID
	Seq       Seq
	Payload   []byte
	Kind      UpdateKind
	CreatedAt time.Time
}
