// Package ws implements the encrypted WebSocket transport, session lifecycle, and application router.
package ws

import (
	"sync"

	"github.com/google/uuid"
)

// ConnectionRegistry tracks in-memory WebSocket sessions active on this server instance.
type ConnectionRegistry interface {
	Add(session *Session)
	Remove(session *Session)

	ForUser(userID uuid.UUID) []*Session
	ForSession(sessionID uuid.UUID) []*Session
	ForDevice(deviceID uuid.UUID) []*Session
	Count() int
	CloseAll(reason string)
}

// LocalConnectionRegistry implements ConnectionRegistry.
type LocalConnectionRegistry struct {
	mu       sync.RWMutex
	sessions map[*Session]struct{}
}

// NewConnectionRegistry constructs a LocalConnectionRegistry.
func NewConnectionRegistry() *LocalConnectionRegistry {
	return &LocalConnectionRegistry{
		sessions: make(map[*Session]struct{}),
	}
}

// Add registers an active session.
func (r *LocalConnectionRegistry) Add(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.sessions[s] = struct{}{}
}

// Remove unregisters a closed session.
func (r *LocalConnectionRegistry) Remove(s *Session) {
	r.mu.Lock()
	defer r.mu.Unlock()
	delete(r.sessions, s)
}

// ForUser returns all active sessions for a user on this instance.
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

// ForSession returns all connections bound to a specific session ID.
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

// ForDevice returns all connections bound to a specific device ID.
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

// Count returns the number of active connections.
func (r *LocalConnectionRegistry) Count() int {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return len(r.sessions)
}

// CloseAll terminates all active connections with a close reason.
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
