package session

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound is returned when a session cannot be located.
	ErrNotFound = errors.New("session: not found")
	// ErrExpired is returned when a session has passed its expiration time.
	ErrExpired = errors.New("session: expired")
	// ErrRevoked is returned when a session has been revoked.
	ErrRevoked = errors.New("session: revoked")
	// ErrInvalidToken is returned when a presented session token is malformed.
	ErrInvalidToken = errors.New("session: invalid token")
)

// Session represents an authenticated user session.
type Session struct {
	ID         uuid.UUID
	TokenHash  []byte
	UserID     uuid.UUID
	IdentityID uuid.UUID
	DeviceID   *uuid.UUID
	CreatedAt  time.Time
	ExpiresAt  time.Time
	RevokedAt  *time.Time
}

// IsValid checks whether the session is active, unexpired, and unrevoked.
func (s *Session) IsValid() bool {
	if s.RevokedAt != nil {
		return false
	}
	return time.Now().Before(s.ExpiresAt)
}
