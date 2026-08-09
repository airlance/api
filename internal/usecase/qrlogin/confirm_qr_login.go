package qrlogin

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/airlance/api/internal/domain/qrlogin"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/domain/transaction"
	"github.com/airlance/api/internal/domain/user"
	"github.com/airlance/api/internal/domain/userdevice"
)

type ConfirmQRLoginUseCase struct {
	store      qrlogin.Store
	identities authidentity.Repository
	devices    userdevice.Repository
	sessions   session.Repository
	cache      session.SessionCache
	users      user.Repository
	tx         transaction.TxManager
	now        func() time.Time
}

func NewConfirmQRLoginUseCase(
	store qrlogin.Store,
	identities authidentity.Repository,
	devices userdevice.Repository,
	sessions session.Repository,
	cache session.SessionCache,
	users user.Repository,
	tx transaction.TxManager,
) *ConfirmQRLoginUseCase {
	return &ConfirmQRLoginUseCase{
		store:      store,
		identities: identities,
		devices:    devices,
		sessions:   sessions,
		cache:      cache,
		users:      users,
		tx:         tx,
		now:        time.Now,
	}
}

var ErrUserDeactivated = errors.New("qrlogin: user is deactivated")

type ConfirmQRLoginOutput struct {
	ServerInstanceID   string
	Token              string
	WaiterAuthKeyID    uint64
	WaiterResumeSecret string
	UserID             int32
}

func (uc *ConfirmQRLoginUseCase) Execute(ctx context.Context, token string, approverUserID int32) (*ConfirmQRLoginOutput, error) {
	confirmed, err := uc.store.MarkConfirmed(ctx, token, approverUserID)
	if err != nil {
		return nil, fmt.Errorf("mark qr login confirmed: %w", err)
	}

	resumeSecret, resumeSecretHash, err := generateResumeSecret()
	if err != nil {
		return nil, fmt.Errorf("generate waiter resume secret: %w", err)
	}

	err = uc.tx.WithinTx(ctx, func(ctx context.Context) error {
		u, err := uc.users.GetByID(ctx, approverUserID)
		if err != nil {
			return fmt.Errorf("get approver user: %w", err)
		}
		if !u.IsActive() {
			return ErrUserDeactivated
		}

		identity, err := uc.identities.GetAnyByUserID(ctx, approverUserID)
		if err != nil {
			return fmt.Errorf("get approver identity: %w", err)
		}

		fingerprint := userdevice.ComputeFingerprint(confirmed.WaiterClientCtx)
		device, err := uc.devices.GetOrCreate(ctx, approverUserID, fingerprint, confirmed.WaiterClientCtx)
		if err != nil {
			return fmt.Errorf("resolve waiter device: %w", err)
		}

		sess := &session.Session{
			AuthKeyID:        confirmed.WaiterAuthKeyID,
			UserID:           approverUserID,
			AuthIdentityID:   identity.ID,
			DeviceID:         &device.ID,
			IPAddress:        confirmed.WaiterClientCtx.IPAddress,
			UserAgent:        confirmed.WaiterClientCtx.UserAgent,
			ResumeSecretHash: resumeSecretHash,
		}
		if err := uc.sessions.Create(ctx, sess); err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		return nil
	})
	if err != nil {
		return nil, err
	}

	_ = uc.cache.Set(ctx, confirmed.WaiterAuthKeyID, session.CacheEntry{
		UserID: approverUserID,
	})

	_ = uc.store.Delete(ctx, token)

	return &ConfirmQRLoginOutput{
		ServerInstanceID:   confirmed.ServerInstanceID,
		Token:              token,
		WaiterAuthKeyID:    confirmed.WaiterAuthKeyID,
		WaiterResumeSecret: resumeSecret,
		UserID:             approverUserID,
	}, nil
}

func generateResumeSecret() (raw string, hash string, err error) {
	buf := make([]byte, 32)
	if _, err := rand.Read(buf); err != nil {
		return "", "", fmt.Errorf("generate resume secret: %w", err)
	}
	raw = base64.RawURLEncoding.EncodeToString(buf)
	sum := sha256.Sum256([]byte(raw))
	return raw, base64.StdEncoding.EncodeToString(sum[:]), nil
}
