package usecase

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/message"
)

type mockMessageRepo struct {
	msgs map[message.MessageID]message.Message
}

func (m *mockMessageRepo) SaveMessage(ctx context.Context, msg message.Message) error {
	m.msgs[msg.ID] = msg
	return nil
}

func (m *mockMessageRepo) GetByID(ctx context.Context, id message.MessageID) (message.Message, error) {
	msg, ok := m.msgs[id]
	if !ok {
		return message.Message{}, message.ErrMessageNotFound
	}
	return msg, nil
}

func (m *mockMessageRepo) UpdateState(ctx context.Context, id message.MessageID, state message.MessageState) error {
	msg, ok := m.msgs[id]
	if !ok {
		return message.ErrMessageNotFound
	}
	msg.State = state
	m.msgs[id] = msg
	return nil
}

func TestMessageUseCase_SendMessage(t *testing.T) {
	ctx := context.Background()
	repo := &mockMessageRepo{msgs: make(map[message.MessageID]message.Message)}
	uc := NewMessageUseCase(repo, nil)

	msg, err := uc.SendMessage(ctx, account.AccountID(1), account.AccountID(2), "c_msg_1", "Hello World!")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	if msg.ClientMsgID != "c_msg_1" {
		t.Fatalf("expected client msg ID c_msg_1, got %s", msg.ClientMsgID)
	}
	if msg.Text != "Hello World!" {
		t.Fatalf("expected text Hello World!, got %s", msg.Text)
	}
	if msg.State != message.StateServerAccepted {
		t.Fatalf("expected state StateServerAccepted, got %v", msg.State)
	}

	_, err = uc.SendMessage(ctx, account.AccountID(1), account.AccountID(0), "c_msg_2", "Hello")
	if err == nil {
		t.Fatal("expected error for recipient ID 0, got nil")
	}
}
