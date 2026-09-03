package ws

import (
	"context"
	"fmt"

	"github.com/google/uuid"

	domainEB "airlance.org/api/internal/domain/eventbus"
)

func (s *Server) StartEventBusListeners(ctx context.Context) error {
	if s.eventBus == nil {
		return nil
	}

	sessionSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicSessionRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe session.revoked error: %w", err)
	}

	deviceSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicDeviceRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe device.revoked error: %w", err)
	}

	userSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicUserSessionsRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe user.sessions_revoked error: %w", err)
	}

	go s.listenRevocationEvents(ctx, sessionSub, func(payload any) {
		if sid, ok := extractUUID(payload); ok {
			for _, conn := range s.registry.ForSession(sid) {
				conn.Close("session_revoked")
			}
		}
	})

	go s.listenRevocationEvents(ctx, deviceSub, func(payload any) {
		if did, ok := extractUUID(payload); ok {
			for _, conn := range s.registry.ForDevice(did) {
				conn.Close("device_revoked")
			}
		}
	})

	go s.listenRevocationEvents(ctx, userSub, func(payload any) {
		if uid, ok := extractUUID(payload); ok {
			for _, conn := range s.registry.ForUser(uid) {
				conn.Close("user_sessions_revoked")
			}
		}
	})

	return nil
}

func extractUUID(payload any) (uuid.UUID, bool) {
	switch v := payload.(type) {
	case uuid.UUID:
		return v, true
	case string:
		id, err := uuid.Parse(v)
		return id, err == nil
	default:
		return uuid.Nil, false
	}
}

func (s *Server) listenRevocationEvents(ctx context.Context, sub domainEB.Subscription, handler func(payload any)) {
	defer func() { _ = sub.Close() }()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.Events():
			if !ok {
				return
			}
			handler(ev.Payload)
		}
	}
}
