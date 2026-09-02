// Package wsticket defines single-use tickets for establishing WebSocket connections.
package wsticket

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound is returned when a ticket does not exist or was already consumed.
	ErrNotFound = errors.New("wsticket: not found or already consumed")
	// ErrExpired is returned when a ticket has expired.
	ErrExpired = errors.New("wsticket: expired")
)

// Ticket represents a short-lived single-use authentication ticket for a WebSocket connection.
type Ticket struct {
	ID        string
	UserID    uuid.UUID
	SessionID uuid.UUID
	DeviceID  *uuid.UUID
	ExpiresAt time.Time
}

// Repository defines atomic storage operations for WebSocket tickets.
type Repository interface {
	Create(ctx context.Context, ticket *Ticket, ttl time.Duration) error
	ConsumeByID(ctx context.Context, id string) (*Ticket, error)
}
