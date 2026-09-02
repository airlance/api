// Package eventbus provides an in-process EventBus implementation.
package eventbus

import (
	"context"
	"sync"

	domainEB "airlance.org/api/internal/domain/eventbus"
)

type localSubscription struct {
	topic  string
	ch     chan domainEB.Event
	bus    *LocalEventBus
	closed bool
	mu     sync.Mutex
}

func (s *localSubscription) Events() <-chan domainEB.Event {
	return s.ch
}

func (s *localSubscription) Close() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if s.closed {
		return nil
	}
	s.closed = true
	close(s.ch)
	s.bus.unsubscribe(s)
	return nil
}

// LocalEventBus implements domainEB.EventBus for in-process messaging.
type LocalEventBus struct {
	mu   sync.RWMutex
	subs map[string][]*localSubscription
}

// NewLocalEventBus constructs a LocalEventBus.
func NewLocalEventBus() *LocalEventBus {
	return &LocalEventBus{
		subs: make(map[string][]*localSubscription),
	}
}

// Publish broadcasts an event to all active subscribers for the topic.
func (b *LocalEventBus) Publish(ctx context.Context, topic string, event domainEB.Event) error {
	b.mu.RLock()
	defer b.mu.RUnlock()

	subscribers := b.subs[topic]
	for _, sub := range subscribers {
		sub.mu.Lock()
		if !sub.closed {
			select {
			case sub.ch <- event:
			default:
				// Non-blocking write: drop if slow subscriber buffer is full
			}
		}
		sub.mu.Unlock()
	}

	return nil
}

// Subscribe registers a subscription channel for a topic.
func (b *LocalEventBus) Subscribe(ctx context.Context, topic string) (domainEB.Subscription, error) {
	b.mu.Lock()
	defer b.mu.Unlock()

	sub := &localSubscription{
		topic: topic,
		ch:    make(chan domainEB.Event, 64),
		bus:   b,
	}

	b.subs[topic] = append(b.subs[topic], sub)
	return sub, nil
}

func (b *LocalEventBus) unsubscribe(sub *localSubscription) {
	b.mu.Lock()
	defer b.mu.Unlock()

	list := b.subs[sub.topic]
	for i, s := range list {
		if s == sub {
			b.subs[sub.topic] = append(list[:i], list[i+1:]...)
			break
		}
	}
}
