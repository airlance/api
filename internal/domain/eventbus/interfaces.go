package eventbus

import (
	"context"
)

type Subscription interface {
	Events() <-chan Event
	Close() error
}

type EventBus interface {
	Publish(ctx context.Context, topic string, event Event) error
	Subscribe(ctx context.Context, topic string) (Subscription, error)
}
