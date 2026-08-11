package message

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/account"
)

var (
	ErrInvalidRecipient = errors.New("invalid recipient account")
	ErrMessageNotFound  = errors.New("message not found")
)

type MessageState uint8

const (
	StateSent           MessageState = 1
	StateServerAccepted MessageState = 2
	StateDelivered      MessageState = 3
	StateRead           MessageState = 4
)

type MessageID string

type Message struct {
	ID                 MessageID
	ClientMsgID        string
	SenderAccountID    account.AccountID
	RecipientAccountID account.AccountID
	Text               string
	State              MessageState
	CreatedAt          time.Time
}
