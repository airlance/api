package usecase

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/domain/device"
)

func TestHeartbeatUseCase_HandlePing(t *testing.T) {
	uc := NewHeartbeatUseCase(nil)

	err := uc.HandlePing(context.Background(), device.DeviceID(42))
	if err != nil {
		t.Fatalf("expected nil error on HandlePing, got %v", err)
	}
}
