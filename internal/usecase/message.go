package usecase

import (
	"context"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/message"
)

type ConnectionPusher interface {
	PushToAccount(accountID account.AccountID, frame []byte) bool
}

type MessageUseCase struct {
	messages message.Repository
	pusher   ConnectionPusher
}

func NewMessageUseCase(messages message.Repository, pusher ConnectionPusher) *MessageUseCase {
	return &MessageUseCase{
		messages: messages,
		pusher:   pusher,
	}
}

func (uc *MessageUseCase) SendMessage(
	ctx context.Context,
	senderID account.AccountID,
	recipientID account.AccountID,
	clientMsgID string,
	text string,
) (message.Message, error) {
	if recipientID == 0 {
		return message.Message{}, message.ErrInvalidRecipient
	}

	msgID := message.MessageID(fmt.Sprintf("msg_%d_%d", senderID, time.Now().UnixNano()))
	msg := message.Message{
		ID:                 msgID,
		ClientMsgID:        clientMsgID,
		SenderAccountID:    senderID,
		RecipientAccountID: recipientID,
		Text:               text,
		State:              message.StateServerAccepted,
		CreatedAt:          time.Now(),
	}

	if uc.messages != nil {
		if err := uc.messages.SaveMessage(ctx, msg); err != nil {
			return message.Message{}, err
		}
	}

	return msg, nil
}
