package redis

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/redis/go-redis/v9"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/airlance/api/internal/infrastructure/redisclient"
)

const ticketTTL = 2 * time.Minute

type QRLoginRepository struct {
	client *redisclient.Client
}

var _ qrlogin.Repository = (*QRLoginRepository)(nil)

func NewQRLoginRepository(client *redisclient.Client) *QRLoginRepository {
	return &QRLoginRepository{client: client}
}

func ticketKey(id qrlogin.TicketID) string {
	return "qrlogin:ticket:" + string(id)
}

func (r *QRLoginRepository) Create(ctx context.Context, t qrlogin.Ticket) (qrlogin.Ticket, error) {
	if t.ID == "" {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			return qrlogin.Ticket{}, fmt.Errorf("qrlogin redis: generate ticket id failed: %w", err)
		}
		t.ID = qrlogin.TicketID(hex.EncodeToString(b))
	}
	now := time.Now()
	t.CreatedAt = now
	t.ExpiresAt = now.Add(ticketTTL)
	t.Status = qrlogin.StatusPending

	data, err := json.Marshal(t)
	if err != nil {
		return qrlogin.Ticket{}, fmt.Errorf("qrlogin redis: marshal ticket failed: %w", err)
	}

	key := ticketKey(t.ID)
	if err := r.client.Set(ctx, key, data, ticketTTL).Err(); err != nil {
		return qrlogin.Ticket{}, fmt.Errorf("qrlogin redis: save ticket failed: %w", err)
	}

	return t, nil
}

func (r *QRLoginRepository) Find(ctx context.Context, id qrlogin.TicketID) (qrlogin.Ticket, error) {
	key := ticketKey(id)
	val, err := r.client.Get(ctx, key).Result()
	if err != nil {
		if errors.Is(err, redis.Nil) {
			return qrlogin.Ticket{}, qrlogin.ErrTicketNotFound
		}
		return qrlogin.Ticket{}, fmt.Errorf("qrlogin redis: find ticket failed: %w", err)
	}

	var t qrlogin.Ticket
	if err := json.Unmarshal([]byte(val), &t); err != nil {
		return qrlogin.Ticket{}, fmt.Errorf("qrlogin redis: unmarshal ticket failed: %w", err)
	}

	if time.Now().After(t.ExpiresAt) {
		return qrlogin.Ticket{}, qrlogin.ErrTicketExpired
	}

	return t, nil
}

func (r *QRLoginRepository) updateTicket(ctx context.Context, id qrlogin.TicketID, updateFn func(t *qrlogin.Ticket) error) error {
	key := ticketKey(id)

	return r.client.Watch(ctx, func(tx *redis.Tx) error {
		val, err := tx.Get(ctx, key).Result()
		if err != nil {
			if errors.Is(err, redis.Nil) {
				return qrlogin.ErrTicketNotFound
			}
			return err
		}

		var t qrlogin.Ticket
		if err := json.Unmarshal([]byte(val), &t); err != nil {
			return err
		}

		if time.Now().After(t.ExpiresAt) {
			return qrlogin.ErrTicketExpired
		}

		if err := updateFn(&t); err != nil {
			return err
		}

		ttl, err := tx.TTL(ctx, key).Result()
		if err != nil || ttl <= 0 {
			ttl = ticketTTL
		}

		data, err := json.Marshal(t)
		if err != nil {
			return err
		}

		_, err = tx.TxPipelined(ctx, func(pipe redis.Pipeliner) error {
			pipe.Set(ctx, key, data, ttl)
			return nil
		})
		return err
	}, key)
}

func (r *QRLoginRepository) MarkScanned(ctx context.Context, id qrlogin.TicketID) error {
	return r.updateTicket(ctx, id, func(t *qrlogin.Ticket) error {
		if t.Status != qrlogin.StatusPending {
			return qrlogin.ErrAlreadyScanned
		}
		t.Status = qrlogin.StatusScanned
		return nil
	})
}

func (r *QRLoginRepository) Confirm(ctx context.Context, id qrlogin.TicketID, accountID account.AccountID, deviceID device.DeviceID) error {
	return r.updateTicket(ctx, id, func(t *qrlogin.Ticket) error {
		if t.Status != qrlogin.StatusScanned {
			return fmt.Errorf("qrlogin: ticket must be scanned before confirm")
		}
		t.Status = qrlogin.StatusConfirmed
		t.AccountID = &accountID
		t.DeviceID = &deviceID
		return nil
	})
}

func (r *QRLoginRepository) Deny(ctx context.Context, id qrlogin.TicketID) error {
	return r.updateTicket(ctx, id, func(t *qrlogin.Ticket) error {
		t.Status = qrlogin.StatusDenied
		return nil
	})
}

func (r *QRLoginRepository) Delete(ctx context.Context, id qrlogin.TicketID) error {
	key := ticketKey(id)
	return r.client.Del(ctx, key).Err()
}
