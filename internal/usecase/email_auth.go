package usecase

import (
	"context"
	"crypto/sha256"
	"fmt"
	"math/rand"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/infrastructure/logger"
)

type EmailAuthUseCase struct {
	accounts   account.Repository
	identities authidentity.Repository
	devices    device.Repository
	sessions   session.Repository
	codes      account.ConfirmationCodeRepository
	email      account.EmailSender
	notifier   device.NewDeviceNotifier
}

func NewEmailAuthUseCase(
	accounts account.Repository,
	identities authidentity.Repository,
	devices device.Repository,
	sessions session.Repository,
	codes account.ConfirmationCodeRepository,
	email account.EmailSender,
	notifier device.NewDeviceNotifier,
) *EmailAuthUseCase {
	return &EmailAuthUseCase{
		accounts:   accounts,
		identities: identities,
		devices:    devices,
		sessions:   sessions,
		codes:      codes,
		email:      email,
		notifier:   notifier,
	}
}

type RequestCodeRequest struct {
	Email     string
	FirstName string
	LastName  string
}

func (uc *EmailAuthUseCase) RequestCode(ctx context.Context, req RequestCodeRequest) error {
	acc, err := uc.accounts.FindByEmail(ctx, req.Email)
	if err != nil {
		if err == account.ErrAccountNotFound {
			acc, err = uc.accounts.CreateAccount(ctx, req.Email, req.FirstName, req.LastName)
			if err != nil {
				return fmt.Errorf("email auth: create account failed: %w", err)
			}
		} else {
			return fmt.Errorf("email auth: find account failed: %w", err)
		}
	}

	code := fmt.Sprintf("%06d", rand.Intn(1000000))
	hash := sha256.Sum256([]byte(code))

	expiresAt := time.Now().Add(15 * time.Minute)
	if err := uc.codes.SaveCode(ctx, acc.ID, hash[:], expiresAt); err != nil {
		return fmt.Errorf("email auth: save code failed: %w", err)
	}

	if uc.email != nil {
		if err := uc.email.SendConfirmationCode(ctx, req.Email, code); err != nil {
			return fmt.Errorf("email auth: send email failed: %w", err)
		}
	}

	return nil
}

type ConfirmCodeRequest struct {
	AccountID account.AccountID
	Code      string
	Device    DeviceInfo
}

func (uc *EmailAuthUseCase) ConfirmCode(ctx context.Context, req ConfirmCodeRequest) (session.Session, error) {
	hash := sha256.Sum256([]byte(req.Code))
	if err := uc.codes.ConsumeCode(ctx, req.AccountID, hash[:]); err != nil {
		return session.Session{}, err
	}

	if err := uc.accounts.ConfirmAccount(ctx, req.AccountID); err != nil {
		return session.Session{}, fmt.Errorf("email auth: confirm account failed: %w", err)
	}

	acc, err := uc.accounts.FindByID(ctx, req.AccountID)
	if err != nil {
		return session.Session{}, fmt.Errorf("email auth: find account failed: %w", err)
	}

	_, err = uc.identities.FindByProviderUserID(ctx, authidentity.ProviderEmail, acc.Email)
	if err == authidentity.ErrIdentityNotFound {
		_, _ = uc.identities.Create(ctx, authidentity.AuthIdentity{
			AccountID:      acc.ID,
			Provider:       authidentity.ProviderEmail,
			ProviderUserID: acc.Email,
			ProviderEmail:  acc.Email,
			Metadata:       map[string]any{},
		})
	}

	dev, wasCreated, err := upsertDevice(ctx, uc.devices, req.AccountID, req.Device)
	if err != nil {
		return session.Session{}, fmt.Errorf("email auth: upsert device failed: %w", err)
	}

	if wasCreated && uc.notifier != nil {
		bgCtx := context.Background()
		go func() {
			if err := uc.notifier.NotifyNewDevice(bgCtx, acc.Email, dev); err != nil {
				logger.FromContext(ctx).WithField("error", err).Warn("failed to send new device notification")
			}
		}()
	}

	sess, err := uc.sessions.CreateSession(ctx, dev.ID, req.AccountID)
	if err != nil {
		return session.Session{}, fmt.Errorf("email auth: create session failed: %w", err)
	}

	return sess, nil
}
