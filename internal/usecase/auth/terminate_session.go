package auth

import (
	"context"
	"fmt"

	"github.com/airlance/api/internal/domain/session"
)

type TerminateSessionUseCase struct {
	sessions session.Repository
	cache    session.SessionCache
}

func NewTerminateSessionUseCase(sessions session.Repository, cache session.SessionCache) *TerminateSessionUseCase {
	return &TerminateSessionUseCase{sessions: sessions, cache: cache}
}

type TerminateSessionInput struct {
	TargetAuthKeyID uint64
	Reason          session.RevokeReason
}

func (uc *TerminateSessionUseCase) Execute(ctx context.Context, in TerminateSessionInput) error {
	reason := in.Reason
	if reason == "" {
		reason = session.RevokeReasonLogout
	}

	if err := uc.sessions.Revoke(ctx, in.TargetAuthKeyID, reason); err != nil {
		return fmt.Errorf("terminate: revoke in postgres: %w", err)
	}

	if err := uc.cache.Delete(ctx, in.TargetAuthKeyID); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheWarmupFailed, err)
	}

	return nil
}
