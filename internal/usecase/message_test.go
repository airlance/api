package usecase

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/message"
	"github.com/airlance/api/internal/domain/updatelog"
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

type mockUpdateLogRepo struct {
	updates []updatelog.Update
	seq     updatelog.Seq
}

func (m *mockUpdateLogRepo) Append(ctx context.Context, accountID account.AccountID, kind updatelog.UpdateKind, payload []byte) (updatelog.Seq, error) {
	m.seq++
	u := updatelog.Update{
		AccountID: accountID,
		Seq:       m.seq,
		Payload:   payload,
		Kind:      kind,
	}
	m.updates = append(m.updates, u)
	return m.seq, nil
}

func (m *mockUpdateLogRepo) ListSince(ctx context.Context, accountID account.AccountID, sinceSeq updatelog.Seq, limit int) ([]updatelog.Update, updatelog.Seq, bool, error) {
	var res []updatelog.Update
	for _, u := range m.updates {
		if u.AccountID == accountID && u.Seq > sinceSeq {
			res = append(res, u)
		}
	}
	hasMore := false
	if len(res) > limit {
		hasMore = true
		res = res[:limit]
	}
	return res, m.seq, hasMore, nil
}

func (m *mockUpdateLogRepo) CurrentSeq(ctx context.Context, accountID account.AccountID) (updatelog.Seq, error) {
	return m.seq, nil
}

type mockUOW struct {
	repo    message.Repository
	updates updatelog.Repository
}

func (u *mockUOW) Execute(ctx context.Context, fn func(ctx context.Context, s TxStore) error) error {
	return fn(ctx, TxStore{Messages: u.repo, Updates: u.updates})
}

func TestMessageUseCase_SendMessage(t *testing.T) {
	ctx := context.Background()
	repo := &mockMessageRepo{msgs: make(map[message.MessageID]message.Message)}
	updatesRepo := &mockUpdateLogRepo{}
	uow := &mockUOW{repo: repo, updates: updatesRepo}

	uc := NewMessageUseCase(uow, updatesRepo, nil)

	msg, seq, err := uc.SendMessage(ctx, account.AccountID(1), account.AccountID(2), "c_msg_1", "Hello World!")
	if err != nil {
		t.Fatalf("SendMessage failed: %v", err)
	}
	if seq != 1 {
		t.Fatalf("expected seq 1, got %d", seq)
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

	_, _, err = uc.SendMessage(ctx, account.AccountID(1), account.AccountID(0), "c_msg_2", "Hello")
	if err == nil {
		t.Fatal("expected error for recipient ID 0, got nil")
	}
}

func TestMessageUseCase_GetDifference(t *testing.T) {
	ctx := context.Background()
	repo := &mockMessageRepo{msgs: make(map[message.MessageID]message.Message)}
	updatesRepo := &mockUpdateLogRepo{}
	uow := &mockUOW{repo: repo, updates: updatesRepo}

	uc := NewMessageUseCase(uow, updatesRepo, nil)

	_, _, _ = uc.SendMessage(ctx, account.AccountID(1), account.AccountID(2), "c_msg_1", "Hello 1")
	_, _, _ = uc.SendMessage(ctx, account.AccountID(1), account.AccountID(2), "c_msg_2", "Hello 2")

	updates, curSeq, hasMore, err := uc.GetDifference(ctx, account.AccountID(2), 0, 10)
	if err != nil {
		t.Fatalf("GetDifference failed: %v", err)
	}
	if curSeq != 2 {
		t.Fatalf("expected curSeq 2, got %d", curSeq)
	}
	if len(updates) != 2 {
		t.Fatalf("expected 2 updates, got %d", len(updates))
	}
	if hasMore {
		t.Fatal("expected hasMore = false")
	}
}
