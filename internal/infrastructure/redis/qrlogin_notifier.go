package redis

import (
	"context"
	"encoding/json"
	"fmt"
	"log"

	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/redis/go-redis/v9"
)

const qrLoginPubSubChannel = "qrlogin:events"

type qrLoginEventType string

const (
	qrLoginEventConfirmed qrLoginEventType = "confirmed"
	qrLoginEventExpired   qrLoginEventType = "expired_or_rejected"
)

type qrLoginEvent struct {
	Type             qrLoginEventType `json:"type"`
	ServerInstanceID string           `json:"server_instance_id"`
	Token            string           `json:"token"`
	AuthKeyID        uint64           `json:"auth_key_id,omitempty"`
	UserID           int32            `json:"user_id,omitempty"`
}

type QRLoginNotifier struct {
	client *redis.Client
}

var _ qrlogin.Notifier = (*QRLoginNotifier)(nil)

func NewQRLoginNotifier(client *redis.Client) *QRLoginNotifier {
	return &QRLoginNotifier{client: client}
}

func (n *QRLoginNotifier) PublishConfirmed(ctx context.Context, serverInstanceID, token string, authKeyID uint64, userID int32) error {
	return n.publish(ctx, qrLoginEvent{
		Type:             qrLoginEventConfirmed,
		ServerInstanceID: serverInstanceID,
		Token:            token,
		AuthKeyID:        authKeyID,
		UserID:           userID,
	})
}

func (n *QRLoginNotifier) PublishExpiredOrRejected(ctx context.Context, serverInstanceID, token string) error {
	return n.publish(ctx, qrLoginEvent{
		Type:             qrLoginEventExpired,
		ServerInstanceID: serverInstanceID,
		Token:            token,
	})
}

func (n *QRLoginNotifier) publish(ctx context.Context, ev qrLoginEvent) error {
	raw, err := json.Marshal(ev)
	if err != nil {
		return fmt.Errorf("redis: marshal qrlogin event: %w", err)
	}
	if err := n.client.Publish(ctx, qrLoginPubSubChannel, raw).Err(); err != nil {
		return fmt.Errorf("redis: publish qrlogin event: %w", err)
	}
	return nil
}

func (n *QRLoginNotifier) Subscribe(ctx context.Context, thisInstanceID string, handler qrlogin.EventHandler) error {
	pubsub := n.client.Subscribe(ctx, qrLoginPubSubChannel)

	if _, err := pubsub.Receive(ctx); err != nil {
		return fmt.Errorf("redis: qrlogin subscribe: %w", err)
	}

	go func() {
		ch := pubsub.Channel()
		for {
			select {
			case <-ctx.Done():
				_ = pubsub.Close()
				return
			case msg, ok := <-ch:
				if !ok {
					return
				}
				var ev qrLoginEvent
				if err := json.Unmarshal([]byte(msg.Payload), &ev); err != nil {
					log.Printf("[QRLoginNotifier] failed to unmarshal event: %v\n", err)
					continue
				}
				if ev.ServerInstanceID != thisInstanceID {
					continue
				}
				switch ev.Type {
				case qrLoginEventConfirmed:
					handler.OnConfirmed(ev.Token, ev.AuthKeyID, ev.UserID)
				case qrLoginEventExpired:
					handler.OnExpiredOrRejected(ev.Token)
				default:
					log.Printf("[QRLoginNotifier] unknown event type: %s\n", ev.Type)
				}
			}
		}
	}()

	return nil
}
