package ws

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var (
	ErrServerDraining               = errors.New("ws: server is draining")
	ErrMaxConnectionsReached        = errors.New("ws: global connection limit reached")
	ErrMaxConnectionsPerUserReached = errors.New("ws: user connection limit reached")
	ErrMaxConnectionsPerIPReached   = errors.New("ws: ip connection limit reached")
)

type ConnectionRegistry interface {
	Add(session *Session)
	Remove(session *Session)
	TryRegister(session *Session, maxGlobal, maxPerUser, maxPerIP int) error

	ForUser(userID uuid.UUID) []*Session
	ForSession(sessionID uuid.UUID) []*Session
	ForDevice(deviceID uuid.UUID) []*Session
	Count() int
	CountForIP(ip string) int
	StopAccepting()
	Drain(timeout time.Duration)
	CloseAll(reason string)
}

type LocalConnectionRegistry struct {
	mu       sync.RWMutex
	sessions map[*Session]struct{}
	draining bool
}

func NewConnectionRegistry() *LocalConnectionRegistry {
	return &LocalConnectionRegistry{
		sessions: make(map[*Session]struct{}),
	}
}

func (r *LocalConnectionRegistry) Add(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s] = struct{}{}
}

func (r *LocalConnectionRegistry) Remove(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, s)
}

func (r *LocalConnectionRegistry) TryRegister(s *Session, maxGlobal, maxPerUser, maxPerIP int) error {
	r.mu.Lock()
	defer r.mu.Unlock()

	if r.draining {
		return ErrServerDraining
	}

	if maxGlobal > 0 && len(r.sessions) >= maxGlobal {
		return ErrMaxConnectionsReached
	}

	var userCount int
	var ipCount int

	for active := range r.sessions {
		if active.UserID == s.UserID {
			userCount++
		}
		if s.ClientIP != "" && active.ClientIP == s.ClientIP {
			ipCount++
		}
	}

	if maxPerUser > 0 && userCount >= maxPerUser {
		return ErrMaxConnectionsPerUserReached
	}
	if maxPerIP > 0 && ipCount >= maxPerIP {
		return ErrMaxConnectionsPerIPReached
	}

	r.sessions[s] = struct{}{}
	return nil
}

func (r *LocalConnectionRegistry) ForUser(userID uuid.UUID) []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var res []*Session
	for s := range r.sessions {
		if s.UserID == userID {
			res = append(res, s)
		}
	}
	return res
}

func (r *LocalConnectionRegistry) ForSession(sessionID uuid.UUID) []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var res []*Session
	for s := range r.sessions {
		if s.SessionID == sessionID {
			res = append(res, s)
		}
	}
	return res
}

func (r *LocalConnectionRegistry) ForDevice(deviceID uuid.UUID) []*Session {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var res []*Session
	for s := range r.sessions {
		if s.DeviceID != nil && *s.DeviceID == deviceID {
			res = append(res, s)
		}
	}
	return res
}

func (r *LocalConnectionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

func (r *LocalConnectionRegistry) CountForIP(ip string) int {
	r.mu.RLock()
	defer r.mu.RUnlock()

	var count int
	for s := range r.sessions {
		if s.ClientIP == ip {
			count++
		}
	}
	return count
}

func (r *LocalConnectionRegistry) StopAccepting() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.draining = true
}

func (r *LocalConnectionRegistry) Drain(timeout time.Duration) {
	r.StopAccepting()

	r.mu.RLock()
	all := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		all = append(all, s)
	}
	r.mu.RUnlock()

	for _, s := range all {
		if s.conn != nil {
			_ = s.conn.WriteControl(
				websocket.CloseMessage,
				websocket.FormatCloseMessage(websocket.CloseGoingAway, "server_draining"),
				time.Now().Add(500*time.Millisecond),
			)
		}
	}

	time.Sleep(timeout)

	r.CloseAll("server_draining")
}

func (r *LocalConnectionRegistry) CloseAll(reason string) {
	r.mu.RLock()
	all := make([]*Session, 0, len(r.sessions))
	for s := range r.sessions {
		all = append(all, s)
	}
	r.mu.RUnlock()

	for _, s := range all {
		s.Close(reason)
	}
}
