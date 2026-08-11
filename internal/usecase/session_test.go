package usecase

import (
	"context"
	"testing"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type mockDeviceRepo struct {
	devices map[string]device.Device
}

func (m *mockDeviceRepo) CreateDevice(ctx context.Context, accountID account.AccountID, publicKey []byte) (device.Device, error) {
	dev := device.Device{
		ID:        device.DeviceID(10),
		AccountID: accountID,
		PublicKey: publicKey,
		CreatedAt: time.Now(),
		LastSeen:  time.Now(),
	}
	m.devices[string(publicKey)] = dev
	return dev, nil
}

func (m *mockDeviceRepo) FindByPublicKey(ctx context.Context, publicKey []byte) (device.Device, error) {
	dev, ok := m.devices[string(publicKey)]
	if !ok {
		return device.Device{}, device.ErrDeviceNotFound
	}
	return dev, nil
}

type mockSessionRepo struct {
	sessions map[session.SessionID]session.Session
}

func (m *mockSessionRepo) CreateSession(ctx context.Context, deviceID device.DeviceID, accountID account.AccountID) (session.Session, error) {
	s := session.Session{
		ID:        "sess_test_123",
		DeviceID:  deviceID,
		AccountID: accountID,
		CreatedAt: time.Now(),
	}
	m.sessions[s.ID] = s
	return s, nil
}

func (m *mockSessionRepo) FindSession(ctx context.Context, id session.SessionID) (session.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return session.Session{}, session.ErrSessionNotFound
	}
	return s, nil
}

func (m *mockSessionRepo) DeleteSession(ctx context.Context, id session.SessionID) error {
	delete(m.sessions, id)
	return nil
}

func TestSessionUseCase_NewAndResumeSession(t *testing.T) {
	ctx := context.Background()
	devRepo := &mockDeviceRepo{devices: make(map[string]device.Device)}
	sessRepo := &mockSessionRepo{sessions: make(map[session.SessionID]session.Session)}

	pubKey := []byte("device_public_key_32_bytes_long!")
	_, _ = devRepo.CreateDevice(ctx, 100, pubKey)
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
