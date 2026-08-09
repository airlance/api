package auth

import (
	"context"
	"crypto/subtle"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/domain/user"
)

type ResumeSessionUseCase struct {
	users    user.Repository
	sessions session.Repository
	cache    session.SessionCache
	now      func() time.Time
}

func NewResumeSessionUseCase(
	users user.Repository,
	sessions session.Repository,
	cache session.SessionCache,
) *ResumeSessionUseCase {
	return &ResumeSessionUseCase{
		users:    users,
		sessions: sessions,
		cache:    cache,
		now:      time.Now,
	}
}

type ResumeSessionInput struct {
	AuthKeyID    uint64
	ResumeSecret string
}

type ResumeSessionOutput struct {
	AuthKeyID uint64
	UserID    int32
}

func (uc *ResumeSessionUseCase) Execute(ctx context.Context, in ResumeSessionInput) (*ResumeSessionOutput, error) {
	sess, err := uc.loadActiveSession(ctx, in.AuthKeyID)
	if err != nil {
		return nil, err
	}

	presentedHash := hashResumeSecret(in.ResumeSecret)
	if subtle.ConstantTimeCompare([]byte(sess.ResumeSecretHash), []byte(presentedHash)) != 1 {
		return nil, ErrInvalidResumeSecret
	}

	u, err := uc.users.GetByID(ctx, sess.UserID)
	if err != nil {
		return nil, fmt.Errorf("resume: load user: %w", err)
	}
	if !u.IsActive() {
		return nil, ErrUserDeactivated
	}

	if err := uc.sessions.UpdateLastSeenSeq(ctx, in.AuthKeyID, sess.LastSeenSeq); err != nil {
		return &ResumeSessionOutput{AuthKeyID: sess.AuthKeyID, UserID: sess.UserID},
			fmt.Errorf("resume: update last active: %w", err)
	}

	if err := uc.cache.Set(ctx, sess.AuthKeyID, session.CacheEntry{
		UserID:      sess.UserID,
		LastSeenSeq: sess.LastSeenSeq,
	}); err != nil {
		return &ResumeSessionOutput{AuthKeyID: sess.AuthKeyID, UserID: sess.UserID},
			fmt.Errorf("%w: %v", ErrCacheWarmupFailed, err)
	}

	return &ResumeSessionOutput{AuthKeyID: sess.AuthKeyID, UserID: sess.UserID}, nil
}

func (uc *ResumeSessionUseCase) loadActiveSession(ctx context.Context, authKeyID uint64) (*session.Session, error) {
	entry, err := uc.cache.Get(ctx, authKeyID)
	if err != nil {
		return nil, fmt.Errorf("resume: read cache: %w", err)
	}
	if entry != nil {
		sess, err := uc.sessions.GetActive(ctx, authKeyID)
		if err != nil {
			if errors.Is(err, session.ErrNotFound) {
				_ = uc.cache.Delete(ctx, authKeyID)
				return nil, ErrSessionNotFound
			}
			return nil, fmt.Errorf("resume: verify cache hit against postgres: %w", err)
		}
		return sess, nil
	}

	sess, err := uc.sessions.GetActive(ctx, authKeyID)
	if err != nil {
		if errors.Is(err, session.ErrNotFound) {
			return nil, ErrSessionNotFound
		}
		return nil, fmt.Errorf("resume: read postgres: %w", err)
	}
	return sess, nil
}
