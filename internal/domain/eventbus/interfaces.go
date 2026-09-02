package eventbus

import (
	"context"
)

// Subscription represents an active subscription to a topic with explicit resource cleanup.
type Subscription interface {
	Events() <-chan Event
	Close() error
}

// EventBus defines the publishing and subscription contract.
type EventBus interface {
	Publish(ctx context.Context, topic string, event Event) error
	Subscribe(ctx context.Context, topic string) (Subscription, error)
}
