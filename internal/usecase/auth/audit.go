package auth

import (
	"context"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
)

func (u *Usecase) recordAuthFailure(ctx context.Context, userID *uuid.UUID, ceremony, ip, userAgent, reqID, reason string) error {
	now := time.Now()
	ev := &audit.Event{
		ID:         uuid.New(),
		OccurredAt: now,
		UserID:     userID,
		ActorType:  "anonymous",
		ActorID:    userID,
		EventType:  audit.EventAuthLoginFailed,
		IP:         ip,
		UserAgent:  userAgent,
		RequestID:  reqID,
		Metadata: map[string]any{
			"ceremony": ceremony,
			"reason":   reason,
		},
		CreatedAt: now,
	}
	if ceremony == "signup" {
		ev.EventType = audit.EventAuthSignupFailed
	}
	return u.auditRepo.Record(ctx, ev)
}
