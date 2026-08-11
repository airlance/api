package redis

import (
	"context"
	"encoding/json"
	"fmt"

	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/airlance/api/internal/infrastructure/redisclient"
)

type EventPublisher struct {
	client *redisclient.Client
}

var _ qrlogin.EventPublisher = (*EventPublisher)(nil)

func NewEventPublisher(client *redisclient.Client) *EventPublisher {
	return &EventPublisher{client: client}
}

func EventChannel(nodeID string) string {
	return "qrlogin:events:" + nodeID
}

func (p *EventPublisher) Publish(ctx context.Context, nodeID string, event qrlogin.Event) error {
	data, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("qrlogin pubsub: marshal event failed: %w", err)
	}

	channel := EventChannel(nodeID)
	if err := p.client.Publish(ctx, channel, data).Err(); err != nil {
		return fmt.Errorf("qrlogin pubsub: publish failed: %w", err)
	}

	return nil
}
