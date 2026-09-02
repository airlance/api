package session

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/session"
)

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
