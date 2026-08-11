package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type SessionUseCase struct {
	sessions session.Repository
	devices  device.Repository
}

func NewSessionUseCase(
	sessions session.Repository,
	devices device.Repository,
) *SessionUseCase {
	return &SessionUseCase{
		sessions: sessions,
		devices:  devices,
	}
}

func (uc *SessionUseCase) NewSession(
	ctx context.Context,
	devicePublicKey []byte,
) (session.Session, error) {
	dev, err := uc.devices.FindByPublicKey(ctx, devicePublicKey)
	if err != nil {
		return session.Session{}, err
	}
	return uc.sessions.CreateSession(ctx, dev.ID, dev.AccountID)
}

func (uc *SessionUseCase) ResumeSession(
	ctx context.Context,
	sessionID session.SessionID,
	devicePublicKey []byte,
) (session.Session, error) {
	sess, err := uc.sessions.FindSession(ctx, sessionID)
	if err != nil {
		return session.Session{}, err
	}

	dev, err := uc.devices.FindByPublicKey(ctx, devicePublicKey)
	if err != nil {
		return session.Session{}, err
	}

	if sess.DeviceID != dev.ID {
		return session.Session{}, session.ErrSessionNotFound
	}

	return sess, nil
}
