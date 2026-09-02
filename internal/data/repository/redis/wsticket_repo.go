// Package redis provides Redis implementations for ephemeral data structures like WebSocket tickets.
package redis

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	goredis "github.com/redis/go-redis/v9"

	"airlance.org/api/internal/domain/wsticket"
)

// WSTicketRepository implements wsticket.Repository using Redis.
type WSTicketRepository struct {
	client *goredis.Client
}

// NewWSTicketRepository constructs a WSTicketRepository.
func NewWSTicketRepository(client *goredis.Client) *WSTicketRepository {
	return &WSTicketRepository{client: client}
}

// Create stores a short-lived single-use ticket in Redis.
func (r *WSTicketRepository) Create(ctx context.Context, ticket *wsticket.Ticket, ttl time.Duration) error {
	data, err := json.Marshal(ticket)
	if err != nil {
		return fmt.Errorf("wsticket_repo: marshal failed: %w", err)
	}

	key := fmt.Sprintf("ws:ticket:%s", ticket.ID)
	if err := r.client.Set(ctx, key, data, ttl).Err(); err != nil {
		return fmt.Errorf("wsticket_repo: set failed: %w", err)
	}

	return nil
}

// ConsumeByID atomically retrieves and deletes a ticket.
func (r *WSTicketRepository) ConsumeByID(ctx context.Context, id string) (*wsticket.Ticket, error) {
	key := fmt.Sprintf("ws:ticket:%s", id)

	// Use GETDEL (or fallback Lua script) to guarantee single-use consumption
	res, err := r.client.GetDel(ctx, key).Bytes()
	if err != nil {
		if errors.Is(err, goredis.Nil) {
			return nil, wsticket.ErrNotFound
		}
		return nil, fmt.Errorf("wsticket_repo: getdel failed: %w", err)
	}

	var ticket wsticket.Ticket
	if err := json.Unmarshal(res, &ticket); err != nil {
		return nil, fmt.Errorf("wsticket_repo: unmarshal failed: %w", err)
	}

	if time.Now().After(ticket.ExpiresAt) {
		return nil, wsticket.ErrExpired
	}

	return &ticket, nil
}
