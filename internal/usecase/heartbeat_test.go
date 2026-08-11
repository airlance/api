package usecase

import (
	"context"
	"testing"

	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

func TestHeartbeatUseCase_HandlePing(t *testing.T) {
	uc := NewHeartbeatUseCase(nil, nil)

	err := uc.HandlePing(context.Background(), session.SessionID("sess123"), device.DeviceID(42))
	if err != nil {
		t.Fatalf("expected nil error on HandlePing, got %v", err)
	}
}
