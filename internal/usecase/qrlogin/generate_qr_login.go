package qrlogin

import (
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/clientcontext"
	"github.com/airlance/api/internal/domain/qrlogin"
)

type GenerateQRLoginUseCase struct {
	store            qrlogin.Store
	serverInstanceID string
	now              func() time.Time
}

func NewGenerateQRLoginUseCase(store qrlogin.Store, serverInstanceID string) *GenerateQRLoginUseCase {
	return &GenerateQRLoginUseCase{
		store:            store,
		serverInstanceID: serverInstanceID,
		now:              time.Now,
	}
}

type GenerateQRLoginInput struct {
	WaiterClientCtx clientcontext.ClientContext
}

type GenerateQRLoginOutput struct {
	Token       string
	ExpiresAtMs int64
}

func (uc *GenerateQRLoginUseCase) Execute(ctx context.Context, in GenerateQRLoginInput) (*GenerateQRLoginOutput, error) {
	token, err := generateToken()
	if err != nil {
		return nil, fmt.Errorf("generate qr token: %w", err)
	}

	waiterAuthKeyID, err := generateAuthKeyID()
	if err != nil {
		return nil, fmt.Errorf("generate waiter auth key id: %w", err)
	}

	createdAt := uc.now()
	sess := &qrlogin.Session{
		Token:            token,
		Status:           qrlogin.StatusPending,
		WaiterClientCtx:  in.WaiterClientCtx,
		WaiterAuthKeyID:  waiterAuthKeyID,
		ServerInstanceID: uc.serverInstanceID,
		CreatedAt:        createdAt,
	}

	if err := uc.store.Create(ctx, sess); err != nil {
		return nil, fmt.Errorf("create qr login session: %w", err)
	}

	return &GenerateQRLoginOutput{
		Token:       token,
		ExpiresAtMs: createdAt.Add(qrlogin.TTL).UnixMilli(),
	}, nil
}

func generateToken() (string, error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", err
	}
	return hex.EncodeToString(buf), nil
}

func generateAuthKeyID() (uint64, error) {
	buf := make([]byte, 8)
	if _, err := rand.Read(buf); err != nil {
		return 0, fmt.Errorf("generate auth key id: %w", err)
	}
	return binary.BigEndian.Uint64(buf), nil
}
