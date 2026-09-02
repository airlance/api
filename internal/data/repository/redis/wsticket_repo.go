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

type WSTicketRepository struct {
	client *goredis.Client
}

func NewWSTicketRepository(client *goredis.Client) *WSTicketRepository {
	return &WSTicketRepository{client: client}
}

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

func (r *WSTicketRepository) ConsumeByID(ctx context.Context, id string) (*wsticket.Ticket, error) {
	key := fmt.Sprintf("ws:ticket:%s", id)

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
