package wsticket

import (
	"context"
	"time"
)

// Repository defines atomic storage operations for WebSocket tickets.
type Repository interface {
	Create(ctx context.Context, ticket *Ticket, ttl time.Duration) error
	ConsumeByID(ctx context.Context, id string) (*Ticket, error)
}
