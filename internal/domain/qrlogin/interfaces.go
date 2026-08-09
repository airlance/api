package qrlogin

import "context"

type Store interface {
	Create(ctx context.Context, s *Session) error
	Get(ctx context.Context, token string) (*Session, error)
	MarkScanned(ctx context.Context, token string) (*Session, error)
	MarkConfirmed(ctx context.Context, token string, userID int32) (*Session, error)
	MarkRejected(ctx context.Context, token string) (*Session, error)
	Delete(ctx context.Context, token string) error
}

type Notifier interface {
	PublishConfirmed(ctx context.Context, serverInstanceID, token string, authKeyID uint64, userID int32) error
	PublishExpiredOrRejected(ctx context.Context, serverInstanceID, token string) error
	Subscribe(ctx context.Context, thisInstanceID string, handler EventHandler) error
}

type EventHandler interface {
	OnConfirmed(token string, authKeyID uint64, userID int32)
	OnExpiredOrRejected(token string)
}
