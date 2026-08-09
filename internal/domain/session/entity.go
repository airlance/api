package session

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
)

var ErrNotFound = errors.New("session: not found")

type RevokeReason string

const (
	RevokeReasonLogout   RevokeReason = "logout"
	RevokeReasonAdmin    RevokeReason = "admin"
	RevokeReasonSecurity RevokeReason = "security"
)

type Session struct {
	AuthKeyID        uint64
	UserID           int32
	AuthIdentityID   int64
	DeviceID         *int64
	IPAddress        string
	UserAgent        string
	ResumeSecretHash string
	LastSeenSeq      uint64
	CreatedAt        time.Time
	LastActiveAt     time.Time
	RevokedAt        *time.Time
	RevokedReason    RevokeReason
}

func (s *Session) IsActive() bool {
	return s.RevokedAt == nil
}

type SessionView struct {
	Session
	DeviceName string
	Platform   clientcontext.Platform
	OS         string
}

type CacheEntry struct {
	UserID      int32
	LastSeenSeq uint64
}
