package session

import "context"

type Repository interface {
	Create(ctx context.Context, s *Session) error
	GetActive(ctx context.Context, authKeyID uint64) (*Session, error)
	GetAny(ctx context.Context, authKeyID uint64) (*Session, error)
	ListActiveByUserID(ctx context.Context, userID int32) ([]*SessionView, error)
	UpdateLastSeenSeq(ctx context.Context, authKeyID uint64, seq uint64) error
	Revoke(ctx context.Context, authKeyID uint64, reason RevokeReason) error
	RevokeAllByUserID(ctx context.Context, userID int32, reason RevokeReason) error
}

type SessionCache interface {
	Get(ctx context.Context, authKeyID uint64) (*CacheEntry, error)
	Set(ctx context.Context, authKeyID uint64, entry CacheEntry) error
	Delete(ctx context.Context, authKeyID uint64) error
}
