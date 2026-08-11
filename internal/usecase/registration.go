package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/session"
)

type RegisterAccountRequest struct {
	Email           string
	FirstName       string
	LastName        string
	RemoteIP        string
	DevicePublicKey []byte
}

type ConfirmCodeRequest struct {
	AccountID       account.AccountID
	Code            string
	DevicePublicKey []byte
}

type RegistrationUseCase struct {
	accounts account.Repository
	devices  device.Repository
	codes    account.ConfirmationCodeRepository
	email    account.EmailSender
}

func NewRegistrationUseCase(
	accounts account.Repository,
	devices device.Repository,
	codes account.ConfirmationCodeRepository,
	email account.EmailSender,
) *RegistrationUseCase {
	return &RegistrationUseCase{
		accounts: accounts,
		devices:  devices,
		codes:    codes,
		email:    email,
	}
}

func (uc *RegistrationUseCase) RegisterAccount(
	ctx context.Context,
	req RegisterAccountRequest,
) error {
	return nil
}

func (uc *RegistrationUseCase) ConfirmEmailCode(
	ctx context.Context,
	req ConfirmCodeRequest,
) (session.Session, error) {
	return session.Session{}, nil
}
