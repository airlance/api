package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/device"
)

type HeartbeatUseCase struct {
	devices device.Repository
}

func NewHeartbeatUseCase(devices device.Repository) *HeartbeatUseCase {
	return &HeartbeatUseCase{devices: devices}
}

func (uc *HeartbeatUseCase) HandlePing(ctx context.Context, deviceID device.DeviceID) error {
	return nil
}
