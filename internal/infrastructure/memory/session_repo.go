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

func (r *SessionRepository) TouchLastActive(ctx context.Context, id session.SessionID) error {
	val, ok := r.sessions.Load(id)
	if !ok {
		return session.ErrSessionNotFound
	}
	sess := val.(session.Session)
	sess.LastActiveAt = time.Now()
	r.sessions.Store(id, sess)
	return nil
}

func (r *SessionRepository) ListActiveByAccount(ctx context.Context, accountID account.AccountID) ([]session.Session, error) {
	var res []session.Session
	r.sessions.Range(func(key, value any) bool {
		s := value.(session.Session)
		if s.AccountID == accountID && s.IsActive() {
			res = append(res, s)
		}
		return true
	})
	return res, nil
}

func (r *SessionRepository) Revoke(ctx context.Context, id session.SessionID) error {
	val, ok := r.sessions.Load(id)
	if !ok {
		return session.ErrSessionNotFound
	}
	sess := val.(session.Session)
	now := time.Now()
	sess.RevokedAt = &now
	r.sessions.Store(id, sess)
	return nil
}

func (r *SessionRepository) RevokeAllByAccount(ctx context.Context, accountID account.AccountID, exceptSessionID *session.SessionID) error {
	now := time.Now()
	r.sessions.Range(func(key, value any) bool {
		s := value.(session.Session)
		if s.AccountID == accountID && s.IsActive() {
			if exceptSessionID != nil && s.ID == *exceptSessionID {
				return true
			}
			s.RevokedAt = &now
			r.sessions.Store(s.ID, s)
		}
		return true
	})
	return nil
}

func (r *SessionRepository) RevokeInactiveOlderThan(ctx context.Context, cutoff time.Time) (int, error) {
	count := 0
	now := time.Now()
	r.sessions.Range(func(key, value any) bool {
		s := value.(session.Session)
		if s.IsActive() && s.LastActiveAt.Before(cutoff) {
			s.RevokedAt = &now
			r.sessions.Store(s.ID, s)
			count++
		}
		return true
	})
	return count, nil
}
