// Package apiclient defines external API client registrations, rate limit tiers, and repository contracts.
package apiclient

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrClientNotFound is returned when an API client cannot be found.
	ErrClientNotFound = errors.New("apiclient: not found")
	// ErrClientRevoked is returned when an API client is revoked.
	ErrClientRevoked = errors.New("apiclient: revoked")
	// ErrTierNotFound is returned when a requested rate limit tier is not found.
	ErrTierNotFound = errors.New("apiclient: tier not found")
	// ErrDuplicateName is returned when a user attempts to create a client with an existing active name.
	ErrDuplicateName = errors.New("apiclient: duplicate active client name")
)

// RateLimitTier represents rate limiting allowances assigned to an API client.
type RateLimitTier struct {
	ID                uuid.UUID
	Name              string
	RequestsPerMinute int
	RequestsPerDay    int
	CreatedAt         time.Time
}

// APIClient represents an external application registered to access the API.
type APIClient struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	TierID     uuid.UUID
	Name       string
	SecretHash []byte
	CreatedAt  time.Time
	RevokedAt  *time.Time
}

// IsRevoked checks whether the client registration has been terminated.
func (c *APIClient) IsRevoked() bool {
	return c.RevokedAt != nil
}

// Repository defines storage operations for API clients.
type Repository interface {
	Create(ctx context.Context, client *APIClient) error
	GetByID(ctx context.Context, id uuid.UUID) (*APIClient, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*APIClient, error)
	Revoke(ctx context.Context, id uuid.UUID) error
}

// TierRepository defines storage operations for rate limit tiers.
type TierRepository interface {
	GetByID(ctx context.Context, id uuid.UUID) (*RateLimitTier, error)
	GetByName(ctx context.Context, name string) (*RateLimitTier, error)
}
