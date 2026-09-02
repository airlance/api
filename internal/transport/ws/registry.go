// Package ws implements the encrypted WebSocket transport, session lifecycle, and application router.
package ws

import (
	"errors"
	"sync"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
)

var (
	// ErrServerDraining is returned when the server is draining and refusing new WebSocket upgrades.
	ErrServerDraining = errors.New("ws: server is draining")
	// ErrMaxConnectionsReached is returned when the global WebSocket limit is reached.
	ErrMaxConnectionsReached = errors.New("ws: global connection limit reached")
	// ErrMaxConnectionsPerUserReached is returned when a user has too many active connections.
	ErrMaxConnectionsPerUserReached = errors.New("ws: user connection limit reached")
	// ErrMaxConnectionsPerIPReached is returned when an IP has too many active connections.
	ErrMaxConnectionsPerIPReached = errors.New("ws: ip connection limit reached")
)

// ConnectionRegistry tracks in-memory WebSocket sessions active on this server instance.
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

// LocalConnectionRegistry implements ConnectionRegistry.
type LocalConnectionRegistry struct {
	mu       sync.RWMutex
	sessions map[*Session]struct{}
	draining bool
}

// NewConnectionRegistry constructs a LocalConnectionRegistry.
func NewConnectionRegistry() *LocalConnectionRegistry {
	return &LocalConnectionRegistry{
		sessions: make(map[*Session]struct{}),
	}
}

// Add registers an active session unconditionally.
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

// TryRegister performs atomic checking against limits and registers the session.
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

// CountForIP returns active connections from a given IP address.
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

// StopAccepting marks registry as draining so subsequent upgrade attempts are denied.
func (r *LocalConnectionRegistry) StopAccepting() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.draining = true
}

// Drain sends close frames (Going Away 1001) to all connections, waits a bounded grace period, then force closes.
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

	// Wait bounded grace period
	time.Sleep(timeout)

	r.CloseAll("server_draining")
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
