package usecase

import (
	"context"
	"fmt"
	"time"

	gen "github.com/airlance/api/internal/protocol/generated/Protocol"
	flatbuffers "github.com/google/flatbuffers/go"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/message"
	"github.com/airlance/api/internal/domain/updatelog"
)

type ConnectionPusher interface {
	PushToAccount(accountID account.AccountID, frame []byte) bool
}

type MessageUseCase struct {
	uow     UnitOfWork
	updates updatelog.Repository
	pusher  ConnectionPusher
}

func NewMessageUseCase(
	uow UnitOfWork,
	updates updatelog.Repository,
	pusher ConnectionPusher,
) *MessageUseCase {
	return &MessageUseCase{uow: uow, updates: updates, pusher: pusher}
}

func (uc *MessageUseCase) SendMessage(
	ctx context.Context,
	senderID account.AccountID,
	recipientID account.AccountID,
	clientMsgID string,
	text string,
) (message.Message, updatelog.Seq, error) {
	if recipientID == 0 {
		return message.Message{}, 0, message.ErrInvalidRecipient
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

	var seq updatelog.Seq

	err := uc.uow.Execute(ctx, func(ctx context.Context, s TxStore) error {
		if err := s.Messages.SaveMessage(ctx, msg); err != nil {
			return err
		}
		payload, err := encodeMessageUpdate(msg)
		if err != nil {
			return err
		}
		seq, err = s.Updates.Append(ctx, recipientID, updatelog.KindMessage, payload)
		return err
	})
	if err != nil {
		return message.Message{}, 0, err
	}

	if uc.pusher != nil {
		if frame, err := encodePushFrame(msg, seq); err == nil {
			uc.pusher.PushToAccount(recipientID, frame)
		}
	}

	return msg, seq, nil
}

func encodeMessageUpdate(msg message.Message) ([]byte, error) {
	b := flatbuffers.NewBuilder(256)

	srvID := b.CreateString(string(msg.ID))
	textOff := b.CreateString(msg.Text)

	gen.MessageUpdateStart(b)
	gen.MessageUpdateAddServerMsgId(b, srvID)
	gen.MessageUpdateAddSenderAccountId(b, uint64(msg.SenderAccountID))
	gen.MessageUpdateAddText(b, textOff)
	gen.MessageUpdateAddCreatedAt(b, msg.CreatedAt.Unix())

	mu := gen.MessageUpdateEnd(b)
	b.Finish(mu)

	raw := b.FinishedBytes()
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func encodePushFrame(msg message.Message, seq updatelog.Seq) ([]byte, error) {
	b := flatbuffers.NewBuilder(256)

	srvID := b.CreateString(string(msg.ID))
	textOff := b.CreateString(msg.Text)

	gen.MessageUpdateStart(b)
	gen.MessageUpdateAddServerMsgId(b, srvID)
	gen.MessageUpdateAddSenderAccountId(b, uint64(msg.SenderAccountID))
	gen.MessageUpdateAddText(b, textOff)
	gen.MessageUpdateAddCreatedAt(b, msg.CreatedAt.Unix())
	gen.MessageUpdateAddSeqNo(b, int64(seq))
	mu := gen.MessageUpdateEnd(b)

	gen.EnvelopeStart(b)
	gen.EnvelopeAddBodyType(b, gen.BodyMessageUpdate)
	gen.EnvelopeAddBody(b, mu)
	env := gen.EnvelopeEnd(b)
	b.Finish(env)

	raw := b.FinishedBytes()
	out := make([]byte, len(raw))
	copy(out, raw)
	return out, nil
}

func (uc *MessageUseCase) GetDifference(
	ctx context.Context,
	accountID account.AccountID,
	sinceSeq updatelog.Seq,
	limit int,
) ([]updatelog.Update, updatelog.Seq, bool, error) {
	return uc.updates.ListSince(ctx, accountID, sinceSeq, limit)
}
