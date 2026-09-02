package auth

import (
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/tx"
	"airlance.org/api/internal/domain/user"
	sessionUC "airlance.org/api/internal/usecase/session"
)

// Usecase provides provider-agnostic and passkey-specific authentication use cases.
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
}

// NewUsecase constructs an Auth Usecase.
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
) *Usecase {
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
	}
}
