package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type mockSessionDevRepo struct {
	devices map[string]device.Device
}

func (m *mockSessionDevRepo) CreateDevice(ctx context.Context, dev device.Device) (device.Device, error) {
	dev.ID = device.DeviceID(10)
	dev.FirstSeenAt = time.Now()
	dev.LastSeenAt = time.Now()
	m.devices[string(dev.PublicKey)] = dev
	return dev, nil
}

func (m *mockSessionDevRepo) FindByPublicKey(ctx context.Context, publicKey []byte) (device.Device, error) {
	dev, ok := m.devices[string(publicKey)]
	if !ok {
		return device.Device{}, device.ErrDeviceNotFound
	}
	return dev, nil
}

func (m *mockSessionDevRepo) FindByFingerprint(ctx context.Context, accountID account.AccountID, fingerprint string) (device.Device, error) {
	return device.Device{}, device.ErrDeviceNotFound
}

func (m *mockSessionDevRepo) TouchLastSeen(ctx context.Context, id device.DeviceID) error {
	return nil
}

func (m *mockSessionDevRepo) ListByAccount(ctx context.Context, accountID account.AccountID) ([]device.Device, error) {
	return nil, nil
}

func (m *mockSessionDevRepo) Revoke(ctx context.Context, id device.DeviceID) error {
	return nil
}

type mockSessionSessRepo struct {
	sessions map[session.SessionID]session.Session
}

func (m *mockSessionSessRepo) CreateSession(ctx context.Context, deviceID device.DeviceID, accountID account.AccountID) (session.Session, error) {
	s := session.Session{
		ID:        "sess_test_123",
		DeviceID:  deviceID,
		AccountID: accountID,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockSessionSessRepo) FindSession(ctx context.Context, id session.SessionID) (session.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return session.Session{}, session.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockSessionSessRepo) DeleteSession(ctx context.Context, id session.SessionID) error {
	delete(m.sessions, id)
	return nil
}

func (m *mockSessionSessRepo) TouchLastActive(ctx context.Context, id session.SessionID) error {
	return nil
}

func (m *mockSessionSessRepo) ListActiveByAccount(ctx context.Context, accountID account.AccountID) ([]session.Session, error) {
	return nil, nil
}

func (m *mockSessionSessRepo) Revoke(ctx context.Context, id session.SessionID) error {
	return nil
}

func (m *mockSessionSessRepo) RevokeAllByAccount(ctx context.Context, accountID account.AccountID, exceptSessionID *session.SessionID) error {
	return nil
}

func (m *mockSessionSessRepo) RevokeInactiveOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	return 0, nil
}

func TestSessionUseCase_NewAndResumeSession(t *testing.T) {
	ctx := context.Background()
	devRepo := &mockSessionDevRepo{devices: make(map[string]device.Device)}
	sessRepo := &mockSessionSessRepo{sessions: make(map[session.SessionID]session.Session)}

	pubKey := []byte("device_public_key_32_bytes_long!")
	_, _ = devRepo.CreateDevice(ctx, device.Device{AccountID: 100, PublicKey: pubKey})
	uc := NewSessionUseCase(sessRepo, devRepo)

	sess, err := uc.NewSession(ctx, pubKey)
	if err != nil {
		t.Fatalf("NewSession failed: %v", err)
	}
	if sess.ID != "sess_test_123" {
		t.Fatalf("expected session ID sess_test_123, got %s", sess.ID)
	}

	resumed, err := uc.ResumeSession(ctx, sess.ID, pubKey)
	if err != nil {
		t.Fatalf("ResumeSession failed: %v", err)
	}
	if resumed.ID != sess.ID {
		t.Fatalf("resumed ID %s != original ID %s", resumed.ID, sess.ID)
	}

	_, err = uc.ResumeSession(ctx, sess.ID, []byte("wrong_device_public_key_bytes!"))
	if err == nil {
		t.Fatal("expected ResumeSession with wrong device key to fail")
	}
}
