package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type HeartbeatUseCase struct {
	devices  device.Repository
	sessions session.Repository
}

func NewHeartbeatUseCase(devices device.Repository, sessions session.Repository) *HeartbeatUseCase {
	return &HeartbeatUseCase{
		devices:  devices,
		sessions: sessions,
	}
}

func (uc *HeartbeatUseCase) HandlePing(ctx context.Context, sessionID session.SessionID, deviceID device.DeviceID) error {
	if sessionID != "" && uc.sessions != nil {
		_ = uc.sessions.TouchLastActive(ctx, sessionID)
	}
	if deviceID != 0 && uc.devices != nil {
		_ = uc.devices.TouchLastSeen(ctx, deviceID)
	}
	return nil
}
