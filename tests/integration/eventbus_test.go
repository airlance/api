package integration

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	domainEB "airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/infrastructure/eventbus"
)

func TestEventBus_CrossInstanceRevocationSimulation(t *testing.T) {
	bus := eventbus.NewLocalEventBus()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	// Instance B subscribes to session.revoked
	subB, err := bus.Subscribe(ctx, domainEB.TopicSessionRevoked)
	if err != nil {
		t.Fatalf("failed to subscribe: %v", err)
	}
	defer subB.Close()

	// Instance A processes revocation and publishes
	revokedSessionID := uuid.New()
	err = bus.Publish(ctx, domainEB.TopicSessionRevoked, domainEB.Event{
		Topic:     domainEB.TopicSessionRevoked,
		Payload:   revokedSessionID,
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to publish: %v", err)
	}

	// Verify Instance B receives the revocation event
	select {
	case ev, ok := <-subB.Events():
		if !ok {
			t.Fatalf("channel closed unexpectedly")
		}
		if sid, ok := ev.Payload.(uuid.UUID); !ok || sid != revokedSessionID {
			t.Errorf("expected payload %v, got %v", revokedSessionID, ev.Payload)
		}
	case <-time.After(2 * time.Second):
		t.Fatalf("timed out waiting for revocation event on instance B")
	}
}
