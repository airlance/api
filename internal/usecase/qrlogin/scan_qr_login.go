package qrlogin

import (
	"context"
	"fmt"

	"github.com/airlance/api/internal/domain/clientcontext"
	"github.com/airlance/api/internal/domain/qrlogin"
)

type ScanQRLoginUseCase struct {
	store qrlogin.Store
}

func NewScanQRLoginUseCase(store qrlogin.Store) *ScanQRLoginUseCase {
	return &ScanQRLoginUseCase{store: store}
}

type ScanQRLoginOutput struct {
	WaiterClientCtx clientcontext.ClientContext
}

func (uc *ScanQRLoginUseCase) Execute(ctx context.Context, token string) (*ScanQRLoginOutput, error) {
	sess, err := uc.store.MarkScanned(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("mark qr login scanned: %w", err)
	}

	return &ScanQRLoginOutput{WaiterClientCtx: sess.WaiterClientCtx}, nil
}
