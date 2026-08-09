package qrlogin

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
)

var (
	ErrNotFound    = errors.New("qrlogin: token not found")
	ErrAlreadyUsed = errors.New("qrlogin: token already used")
)

type Status string

const (
	StatusPending   Status = "pending"
	StatusScanned   Status = "scanned"
	StatusConfirmed Status = "confirmed"
	StatusRejected  Status = "rejected"
)

const TTL = 2 * time.Minute

type Session struct {
	Token            string
	Status           Status
	WaiterClientCtx  clientcontext.ClientContext
	WaiterAuthKeyID  uint64
	ServerInstanceID string
	UserID           int32
	CreatedAt        time.Time
}
