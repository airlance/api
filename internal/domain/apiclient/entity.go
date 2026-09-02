package apiclient

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrClientNotFound = errors.New("apiclient: not found")
	ErrClientRevoked  = errors.New("apiclient: revoked")
	ErrTierNotFound   = errors.New("apiclient: tier not found")
	ErrDuplicateName  = errors.New("apiclient: duplicate active client name")
)

type RateLimitTier struct {
	ID                uuid.UUID
	Name              string
	RequestsPerMinute int
	RequestsPerDay    int
	CreatedAt         time.Time
}

type APIClient struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TierID     uuid.UUID
	Name       string
	SecretHash []byte
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

func (c *APIClient) IsRevoked() bool {
	return c.RevokedAt != nil
}
