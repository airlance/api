package account

import (
	"context"
	"time"
)

type Repository interface {
	CreateAccount(ctx context.Context, email, firstName, lastName string) (Account, error)
	FindByEmail(ctx context.Context, email string) (Account, error)
	ConfirmAccount(ctx context.Context, id AccountID) error
}

type ConfirmationCodeRepository interface {
	SaveCode(ctx context.Context, accountID AccountID, codeHash []byte, expiresAt time.Time) error
	ConsumeCode(ctx context.Context, accountID AccountID, codeHash []byte) error
}

type EmailSender interface {
	SendConfirmationCode(ctx context.Context, toEmail, code string) error
}
