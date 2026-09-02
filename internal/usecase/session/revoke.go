package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/session"
)

// Revoke invalidates a session and publishes a session.revoked event.
func (u *Usecase) Revoke(ctx context.Context, token string, ip, userAgent, requestID string) error {
	if token == "" {
		return ErrInvalidToken
	}

	tokenHash := crypto.HashToken(token)
	sess, err := u.sessionRepo.GetValid(ctx, tokenHash)
	if err != nil && !errors.Is(err, session.ErrRevoked) {
		return err
	}

	var sessionID uuid.UUID
	var userID uuid.UUID
	if sess != nil {
		sessionID = sess.ID
		userID = sess.UserID
	}

	now := time.Now()
	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.sessionRepo.Revoke(txCtx, tokenHash); err != nil && !errors.Is(err, session.ErrNotFound) {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventSessionRevoked,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"session_id": sessionID.String(),
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return fmt.Errorf("session usecase: revoke tx failed: %w", err)
	}

	if u.eventBus != nil && sessionID != uuid.Nil {
		_ = u.eventBus.Publish(ctx, eventbus.TopicSessionRevoked, eventbus.Event{
			Topic:     eventbus.TopicSessionRevoked,
			Payload:   sessionID,
			Timestamp: now,
		})
	}

	return nil
}

// RevokeAllForUser invalidates all sessions for a user and publishes a user.sessions_revoked event.
func (u *Usecase) RevokeAllForUser(ctx context.Context, userID uuid.UUID, ip, userAgent, requestID string) error {
	now := time.Now()
	err := u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.sessionRepo.RevokeAllForUser(txCtx, userID); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventSessionRevoked,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"scope": "all_sessions",
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return fmt.Errorf("session usecase: revoke all for user failed: %w", err)
	}

	if u.eventBus != nil {
		_ = u.eventBus.Publish(ctx, eventbus.TopicUserSessionsRevoked, eventbus.Event{
			Topic:     eventbus.TopicUserSessionsRevoked,
			Payload:   userID,
			Timestamp: now,
		})
	}

	return nil
}
