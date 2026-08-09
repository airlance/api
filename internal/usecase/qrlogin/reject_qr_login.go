package qrlogin

import (
	"context"
	"fmt"

	"github.com/airlance/api/internal/domain/qrlogin"
)

type RejectQRLoginUseCase struct {
	store qrlogin.Store
}

func NewRejectQRLoginUseCase(store qrlogin.Store) *RejectQRLoginUseCase {
	return &RejectQRLoginUseCase{store: store}
}

type RejectQRLoginOutput struct {
	ServerInstanceID string
	Token            string
}

func (uc *RejectQRLoginUseCase) Execute(ctx context.Context, token string) (*RejectQRLoginOutput, error) {
	sess, err := uc.store.MarkRejected(ctx, token)
	if err != nil {
		return nil, fmt.Errorf("mark qr login rejected: %w", err)
	}

	_ = uc.store.Delete(ctx, token)

	return &RejectQRLoginOutput{
		ServerInstanceID: sess.ServerInstanceID,
		Token:            token,
	}, nil
}
