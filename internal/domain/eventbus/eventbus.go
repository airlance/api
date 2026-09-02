// Package eventbus defines decoupled publish-subscribe messaging interfaces.
package eventbus

import (
	"context"
	"time"
)

// Standard topic constants for cross-component security event delivery.
const (
	TopicSessionRevoked      = "session.revoked"
	TopicDeviceRevoked       = "device.revoked"
	TopicUserSessionsRevoked = "user.sessions_revoked"
)

// Event encapsulates a published message.
type Event struct {
	Topic     string
	Payload   any
	Timestamp time.Time
}

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
