package session

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound     = errors.New("session: not found")
	ErrExpired      = errors.New("session: expired")
	ErrRevoked      = errors.New("session: revoked")
	ErrInvalidToken = errors.New("session: invalid token")
)

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

func (s *Session) IsValid() bool {
	if s.RevokedAt != nil {
		return false
	}
	return time.Now().Before(s.ExpiresAt)
}
