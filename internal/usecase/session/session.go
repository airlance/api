// Package session implements session management, validation, and revocation use cases.
package session

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/infrastructure/crypto"
	"airlance.org/api/internal/infrastructure/database"
)

var (
	// ErrInvalidToken is returned when an invalid session token is provided.
	ErrInvalidToken = session.ErrInvalidToken
)

// Usecase defines session management operations.
type Usecase struct {
	sessionRepo session.Repository
	auditRepo   audit.Repository
	txManager   database.TxManager
	eventBus    eventbus.EventBus
	sessionTTL  time.Duration
}

// NewUsecase constructs a Session Usecase.
func NewUsecase(
	sessionRepo session.Repository,
	auditRepo audit.Repository,
	txManager database.TxManager,
	eventBus eventbus.EventBus,
	sessionTTL time.Duration,
) *Usecase {
	return &Usecase{
		sessionRepo: sessionRepo,
		auditRepo:   auditRepo,
		txManager:   txManager,
		eventBus:    eventBus,
		sessionTTL:  sessionTTL,
	}
}

// CreateSession creates a new authenticated session and atomically writes an audit record.
func (u *Usecase) CreateSession(
	ctx context.Context,
	userID, identityID uuid.UUID,
	deviceID *uuid.UUID,
	ip, userAgent, requestID string,
) (string, *session.Session, error) {
	token, tokenHash, err := crypto.GenerateOpaqueToken(32)
	if err != nil {
		return "", nil, fmt.Errorf("session usecase: generate token failed: %w", err)
	}

	now := time.Now()
	sess := &session.Session{
		ID:         uuid.New(),
		TokenHash:  tokenHash,
		UserID:     userID,
		IdentityID: identityID,
		DeviceID:   deviceID,
		CreatedAt:  now,
		ExpiresAt:  now.Add(u.sessionTTL),
		RevokedAt:  nil,
	}

	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.sessionRepo.Create(txCtx, sess); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventAuthLoginSuccess,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"session_id": sess.ID.String(),
			},
			CreatedAt: now,
		}
		if deviceID != nil {
			auditEv.Metadata["device_id"] = deviceID.String()
		}

		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return "", nil, fmt.Errorf("session usecase: create session tx failed: %w", err)
	}

	return token, sess, nil
}

// Validate verifies a session token and returns the active Session.
func (u *Usecase) Validate(ctx context.Context, token string) (*session.Session, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	tokenHash := crypto.HashToken(token)
	sess, err := u.sessionRepo.GetValid(ctx, tokenHash)
	if err != nil {
		return nil, err
	}

	return sess, nil
}

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
