package session

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/session"
)

func (u *Usecase) ListActiveForUser(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	return u.sessionRepo.ListByUserID(ctx, userID)
}

func (u *Usecase) RevokeByID(ctx context.Context, sessionID, userID uuid.UUID, ip, userAgent, requestID string) error {
	now := time.Now()
	err := u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.sessionRepo.RevokeByID(txCtx, sessionID); err != nil {
			return err
		}
		return u.auditRepo.Record(txCtx, &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventSessionRevoked,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata:   map[string]any{"session_id": sessionID.String(), "via": "ws_logout"},
			CreatedAt:  now,
		})
	})
	if err != nil {
		return fmt.Errorf("session usecase: revoke by id failed: %w", err)
	}
	if u.eventBus != nil {
		_ = u.eventBus.Publish(ctx, eventbus.TopicSessionRevoked, eventbus.Event{
			Topic:     eventbus.TopicSessionRevoked,
			Payload:   sessionID,
			Timestamp: now,
		})
	}
	return nil
}
