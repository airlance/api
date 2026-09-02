package eventbus

import (
	"context"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"
	goredis "github.com/redis/go-redis/v9"

	domainEB "airlance.org/api/internal/domain/eventbus"
)

type redisSubscription struct {
	topic      string
	ch         chan domainEB.Event
	pubsub     *goredis.PubSub
	cancel     context.CancelFunc
	closed     bool
	mu         sync.Mutex
	closeGroup sync.WaitGroup
}

func (s *redisSubscription) Events() <-chan domainEB.Event {
	return s.ch
}

func (s *redisSubscription) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	if s.cancel != nil {
		s.cancel()
	}
	if s.pubsub != nil {
		_ = s.pubsub.Close()
	}
	s.closeGroup.Wait()
	close(s.ch)
	return nil
}

type RedisEventBus struct {
	redis *goredis.Client
}

var _ domainEB.EventBus = (*RedisEventBus)(nil)

func NewRedisEventBus(redis *goredis.Client) *RedisEventBus {
	return &RedisEventBus{redis: redis}
}

type wireEvent struct {
	Topic     string          `json:"topic"`
	Payload   json.RawMessage `json:"payload"`
	Timestamp time.Time       `json:"timestamp"`
}

func (b *RedisEventBus) Publish(ctx context.Context, topic string, event domainEB.Event) error {
	if b.redis == nil {
		return fmt.Errorf("eventbus: uninitialized redis client")
	}

	payloadBytes, err := json.Marshal(event.Payload)
	if err != nil {
		return fmt.Errorf("eventbus: marshal payload failed: %w", err)
	}

	we := wireEvent{
		Topic:     topic,
		Payload:   payloadBytes,
		Timestamp: event.Timestamp,
	}

	msgBytes, err := json.Marshal(we)
	if err != nil {
		return fmt.Errorf("eventbus: marshal wire event failed: %w", err)
	}

	channel := fmt.Sprintf("events:%s", topic)
	return b.redis.Publish(ctx, channel, msgBytes).Err()
}

func (b *RedisEventBus) Subscribe(ctx context.Context, topic string) (domainEB.Subscription, error) {
	if b.redis == nil {
		return nil, fmt.Errorf("eventbus: uninitialized redis client")
	}

	channel := fmt.Sprintf("events:%s", topic)
	pubsub := b.redis.Subscribe(ctx, channel)

	_, err := pubsub.Receive(ctx)
	if err != nil {
		_ = pubsub.Close()
		return nil, fmt.Errorf("eventbus: redis subscribe failed: %w", err)
	}

	subCtx, cancel := context.WithCancel(context.Background())
	sub := &redisSubscription{
		topic:  topic,
		ch:     make(chan domainEB.Event, 64),
		pubsub: pubsub,
		cancel: cancel,
	}

	sub.closeGroup.Add(1)
	go func() {
		defer sub.closeGroup.Done()
		msgCh := pubsub.Channel()
		for {
			select {
			case <-subCtx.Done():
				return
			case msg, ok := <-msgCh:
				if !ok {
					return
				}
				var we wireEvent
				if err := json.Unmarshal([]byte(msg.Payload), &we); err == nil {
					payload := decodePayloadForTopic(we.Topic, we.Payload)

					ev := domainEB.Event{
						Topic:     we.Topic,
						Payload:   payload,
						Timestamp: we.Timestamp,
					}

					select {
					case sub.ch <- ev:
					default:
						// Drop if buffer full to avoid blocking receive loop
					}
				}
			}
		}
	}()

	return sub, nil
}

func decodePayloadForTopic(topic string, raw json.RawMessage) any {
	switch topic {
	case domainEB.TopicSessionRevoked, domainEB.TopicDeviceRevoked, domainEB.TopicUserSessionsRevoked:
		var idStr string
		if err := json.Unmarshal(raw, &idStr); err == nil {
			if id, err := uuid.Parse(idStr); err == nil {
				return id
			}
		}
		var id uuid.UUID
		if err := json.Unmarshal(raw, &id); err == nil {
			return id
		}
	}
	var fallback any
	_ = json.Unmarshal(raw, &fallback)
	return fallback
}
