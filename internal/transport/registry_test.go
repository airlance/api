package transport

import (
	"testing"
	"time"

	"github.com/airlance/api/internal/domain/account"
)

type mockNoiseConn struct {
	written [][]byte
}

func (m *mockNoiseConn) ReadFrame() ([]byte, error) { return nil, nil }
func (m *mockNoiseConn) WriteFrame(data []byte) error {
	m.written = append(m.written, data)
	return nil
}
func (m *mockNoiseConn) SetReadDeadline(t time.Time) error { return nil }
func (m *mockNoiseConn) RemoteStaticKey() []byte           { return []byte("pubkey") }
func (m *mockNoiseConn) Close() error                      { return nil }

func TestConnectionRegistry_RegisterAndGet(t *testing.T) {
	reg := NewConnectionRegistry()

	active := reg.Register(nil, account.AccountID(42))
	if active.ID == "" {
		t.Fatal("expected non-empty connection ID")
	}
	if active.AccountID != 42 {
		t.Fatalf("expected AccountID 42, got %d", active.AccountID)
	}

	got, ok := reg.Get(active.ID)
	if !ok {
		t.Fatalf("expected to find connection with ID %s", active.ID)
	}
	if got.ID != active.ID {
		t.Fatalf("got ID %s, want %s", got.ID, active.ID)
	}

	if reg.Count() != 1 {
		t.Fatalf("count = %d, want 1", reg.Count())
	}

	reg.Unregister(active.ID)
	if _, ok := reg.Get(active.ID); ok {
		t.Fatal("expected connection to be unregistered")
	}
	if reg.Count() != 0 {
		t.Fatalf("count = %d, want 0", reg.Count())
	}
}

func TestConnectionRegistry_PushToAccount(t *testing.T) {
	reg := NewConnectionRegistry()
	mockConn := &mockNoiseConn{}

	ac := reg.Register(mockConn, account.AccountID(100))
	frame := []byte("hello")

	sent := reg.PushToAccount(account.AccountID(100), frame)
	if !sent {
		t.Fatal("expected PushToAccount to return true")
	}
	if len(mockConn.written) != 1 {
		t.Fatalf("expected 1 frame written, got %d", len(mockConn.written))
	}

	// Push to non-existent account
	sentNotFound := reg.PushToAccount(account.AccountID(999), frame)
	if sentNotFound {
		t.Fatal("expected PushToAccount for non-existent account to return false")
	}

	reg.Unregister(ac.ID)
	sentAfterUnregister := reg.PushToAccount(account.AccountID(100), frame)
	if sentAfterUnregister {
		t.Fatal("expected PushToAccount after unregister to return false")
	}
}
