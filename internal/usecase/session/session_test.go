package session

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/session"
)

type mockTxManager struct{}

func (m *mockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type mockSessionRepo struct {
	sessions map[string]*session.Session
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{sessions: make(map[string]*session.Session)}
}

func (m *mockSessionRepo) Create(ctx context.Context, s *session.Session) error {
	m.sessions[string(s.TokenHash)] = s
	return nil
}

func (m *mockSessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	s, ok := m.sessions[string(tokenHash)]
	if !ok {
		return nil, session.ErrNotFound
	}
	if s.RevokedAt != nil {
		return nil, session.ErrRevoked
	}
	if time.Now().After(s.ExpiresAt) {
		return nil, session.ErrExpired
	}
	return s, nil
}

func (m *mockSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, session.ErrNotFound
}

func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	now := time.Now()
	var list []*session.Session
	for _, s := range m.sessions {
		if s.UserID == userID && s.RevokedAt == nil && s.ExpiresAt.After(now) {
			list = append(list, s)
		}
	}
	return list, nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, tokenHash []byte) error {
	s, ok := m.sessions[string(tokenHash)]
	if !ok {
		return session.ErrNotFound
	}
	s.RevokedAt = new(time.Now())
	return nil
}

func (m *mockSessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error {
	for _, s := range m.sessions {
		if s.ID == id {
			s.RevokedAt = new(time.Now())
			return nil
		}
	}
	return session.ErrNotFound
}

func (m *mockSessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	for _, s := range m.sessions {
		if s.UserID == userID {
			s.RevokedAt = &now
		}
	}
	return nil
}

func (m *mockSessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	now := time.Now()
	for _, s := range m.sessions {
		if s.DeviceID != nil && *s.DeviceID == deviceID {
			s.RevokedAt = &now
		}
	}
	return nil
}

func (m *mockSessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	var count int64
	for k, s := range m.sessions {
		if s.ExpiresAt.Before(before) {
			delete(m.sessions, k)
			count++
		}
	}
	return count, nil
}

type mockAuditRepo struct {
	events []*audit.Event
}

func (m *mockAuditRepo) Record(ctx context.Context, e *audit.Event) error {
	m.events = append(m.events, e)
	return nil
}

func TestSessionUsecase_Lifecycle(t *testing.T) {
	sessionRepo := newMockSessionRepo()
	auditRepo := &mockAuditRepo{}
	txManager := &mockTxManager{}

	uc := NewUsecase(sessionRepo, auditRepo, txManager, nil, 1*time.Hour)

	ctx := context.Background()
	userID := uuid.New()
	identID := uuid.New()

	token, sess, err := uc.CreateSession(ctx, userID, identID, nil, "127.0.0.1", "test-agent", "req-1")
	if err != nil {
		t.Fatalf("unexpected create session error: %v", err)
	}
	if token == "" || sess == nil {
		t.Fatalf("expected valid token and session")
	}

	if len(auditRepo.events) != 1 || auditRepo.events[0].EventType != audit.EventAuthLoginSuccess {
		t.Errorf("expected login success audit event, got %v", auditRepo.events)
	}

	validSess, err := uc.Validate(ctx, token)
	if err != nil {
		t.Fatalf("unexpected validate error: %v", err)
	}
	if validSess.ID != sess.ID {
		t.Errorf("expected session ID %v, got %v", sess.ID, validSess.ID)
	}

	if err := uc.Revoke(ctx, token, "127.0.0.1", "test-agent", "req-2"); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}

	if len(auditRepo.events) != 2 || auditRepo.events[1].EventType != audit.EventSessionRevoked {
		t.Errorf("expected session revoked audit event, got %v", auditRepo.events)
	}

	_, err = uc.Validate(ctx, token)
	if err == nil {
		t.Errorf("expected error validating revoked session")
	}
}

func TestUsecase_ListActiveForUser(t *testing.T) {
	sessionRepo := newMockSessionRepo()
	auditRepo := &mockAuditRepo{}
	txManager := &mockTxManager{}
	uc := NewUsecase(sessionRepo, auditRepo, txManager, nil, 1*time.Hour)

	ctx := context.Background()
	userID := uuid.New()
	identID := uuid.New()

	_, sess1, err := uc.CreateSession(ctx, userID, identID, nil, "127.0.0.1", "agent-1", "req-1")
	if err != nil {
		t.Fatalf("unexpected create session 1 error: %v", err)
	}
	_, sess2, err := uc.CreateSession(ctx, userID, identID, nil, "127.0.0.1", "agent-2", "req-2")
	if err != nil {
		t.Fatalf("unexpected create session 2 error: %v", err)
	}

	sessions, err := uc.ListActiveForUser(ctx, userID)
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if len(sessions) != 2 {
		t.Fatalf("expected 2 active sessions, got %d", len(sessions))
	}

	// Revoke sess1 by ID
	if err := uc.RevokeByID(ctx, sess1.ID, userID, "127.0.0.1", "agent-1", "req-3"); err != nil {
		t.Fatalf("unexpected revoke by id error: %v", err)
	}

	sessions, err = uc.ListActiveForUser(ctx, userID)
	if err != nil {
		t.Fatalf("unexpected list error: %v", err)
	}
	if len(sessions) != 1 || sessions[0].ID != sess2.ID {
		t.Fatalf("expected 1 remaining active session (sess2), got %d", len(sessions))
	}

	// Verify audit event
	lastEvent := auditRepo.events[len(auditRepo.events)-1]
	if lastEvent.EventType != audit.EventSessionRevoked {
		t.Errorf("expected EventSessionRevoked, got %s", lastEvent.EventType)
	}
	if lastEvent.Metadata["via"] != "ws_logout" {
		t.Errorf("expected via=ws_logout in metadata, got %v", lastEvent.Metadata)
	}
}
