package memory

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type SessionRepository struct {
	sessions sync.Map
}

var _ session.Repository = (*SessionRepository)(nil)

func NewSessionRepository() *SessionRepository {
	return &SessionRepository{}
}

func (r *SessionRepository) CreateSession(ctx context.Context, deviceID device.DeviceID, accountID account.AccountID) (session.Session, error) {
	sessionID := session.SessionID(fmt.Sprintf("sess_%d_%d", deviceID, time.Now().UnixNano()))
	sess := session.Session{
		ID:        sessionID,
		DeviceID:  deviceID,
		AccountID: accountID,
		CreatedAt: time.Now(),
	}
	r.sessions.Store(sessionID, sess)
	return sess, nil
}

func (r *SessionRepository) FindSession(ctx context.Context, id session.SessionID) (session.Session, error) {
	val, ok := r.sessions.Load(id)
	if !ok {
		return session.Session{}, session.ErrSessionNotFound
	}
	return val.(session.Session), nil
}

func (r *SessionRepository) DeleteSession(ctx context.Context, id session.SessionID) error {
	r.sessions.Delete(id)
	return nil
}
