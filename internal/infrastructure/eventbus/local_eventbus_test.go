package eventbus

import (
	"context"
	"testing"
	"time"

	domainEB "airlance.org/api/internal/domain/eventbus"
)

func TestLocalEventBus_PubSub(t *testing.T) {
	bus := NewLocalEventBus()
	ctx := context.Background()

	sub, err := bus.Subscribe(ctx, domainEB.TopicSessionRevoked)
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer func() { _ = sub.Close() }()

	ev := domainEB.Event{
		Topic:     domainEB.TopicSessionRevoked,
		Payload:   "session-12345",
		Timestamp: time.Now(),
	}

	if err := bus.Publish(ctx, domainEB.TopicSessionRevoked, ev); err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	select {
	case received := <-sub.Events():
		if received.Payload != "session-12345" {
			t.Errorf("expected payload 'session-12345', got %v", received.Payload)
		}
	case <-time.After(1 * time.Second):
		t.Errorf("timeout waiting for event")
	}
}
