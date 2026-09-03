package auth

import (
	"context"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/mailer"
	"airlance.org/api/internal/domain/otp"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/tx"
	"airlance.org/api/internal/domain/user"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type Usecase struct {
	userRepo          user.Repository
	identityRepo      identity.Repository
	passkeyRepo       passkey.CredentialRepo
	challengeRepo     passkey.ChallengeRepo
	deviceRepo        device.Repository
	auditRepo         audit.Repository
	sessionUsecase    *sessionUC.Usecase
	txManager         tx.TxManager
	webAuthnService   passkey.WebAuthnService
	limiter           ratelimit.Limiter
	eventBus          eventbus.EventBus
	deviceHMACKeyRing crypto.KeyRing
	otpRepo           otp.Repository
	mailer            mailer.Sender
	otpHMACKeyRing    crypto.KeyRing
	otpCodeLength     int
	otpTTL            time.Duration
	otpMaxAttempts    int
}

func NewUsecase(
	userRepo user.Repository,
	identityRepo identity.Repository,
	passkeyRepo passkey.CredentialRepo,
	challengeRepo passkey.ChallengeRepo,
	deviceRepo device.Repository,
	auditRepo audit.Repository,
	sessionUsecase *sessionUC.Usecase,
	txManager tx.TxManager,
	webAuthnService passkey.WebAuthnService,
	limiter ratelimit.Limiter,
	eventBus eventbus.EventBus,
	deviceHMACKeyRing crypto.KeyRing,
	otpRepo otp.Repository,
	mailer mailer.Sender,
	otpHMACKeyRing crypto.KeyRing,
	otpCodeLength int,
	otpTTL time.Duration,
	otpMaxAttempts int,
) *Usecase {
	if otpCodeLength <= 0 {
		otpCodeLength = 6
	}
	if otpTTL <= 0 {
		otpTTL = 10 * time.Minute
	}
	if otpMaxAttempts <= 0 {
		otpMaxAttempts = 5
	}
	return &Usecase{
		userRepo:          userRepo,
		identityRepo:      identityRepo,
		passkeyRepo:       passkeyRepo,
		challengeRepo:     challengeRepo,
		deviceRepo:        deviceRepo,
		auditRepo:         auditRepo,
		sessionUsecase:    sessionUsecase,
		txManager:         txManager,
		webAuthnService:   webAuthnService,
		limiter:           limiter,
		eventBus:          eventBus,
		deviceHMACKeyRing: deviceHMACKeyRing,
		otpRepo:           otpRepo,
		mailer:            mailer,
		otpHMACKeyRing:    otpHMACKeyRing,
		otpCodeLength:     otpCodeLength,
		otpTTL:            otpTTL,
		otpMaxAttempts:    otpMaxAttempts,
	}
}

func (u *Usecase) GetUser(ctx context.Context, userID uuid.UUID) (*user.User, error) {
	return u.userRepo.GetByID(ctx, userID)
}
