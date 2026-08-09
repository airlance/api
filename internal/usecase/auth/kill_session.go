package auth

import (
	"context"
	"errors"
	"fmt"

	"github.com/airlance/api/internal/domain/session"
)

type KillSessionUseCase struct {
	sessions session.Repository
	cache    session.SessionCache
}

func NewKillSessionUseCase(sessions session.Repository, cache session.SessionCache) *KillSessionUseCase {
	return &KillSessionUseCase{sessions: sessions, cache: cache}
}

type KillSessionInput struct {
	CallerUserID    int32
	TargetAuthKeyID uint64
}

func (uc *KillSessionUseCase) Execute(ctx context.Context, in KillSessionInput) error {
	target, err := uc.sessions.GetActive(ctx, in.TargetAuthKeyID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return ErrSessionNotFound
		}
		return fmt.Errorf("kill session: load target: %w", err)
	}

	if target.UserID != in.CallerUserID {
		return ErrSessionNotFound
	}

	if err := uc.sessions.Revoke(ctx, in.TargetAuthKeyID, session.RevokeReasonLogout); err != nil {
		return fmt.Errorf("kill session: revoke in postgres: %w", err)
	}

	if err := uc.cache.Delete(ctx, in.TargetAuthKeyID); err != nil {
		return fmt.Errorf("%w: %v", ErrCacheWarmupFailed, err)
	}

	return nil
}
