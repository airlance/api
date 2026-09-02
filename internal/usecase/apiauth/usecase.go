package apiauth

import (
	"time"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/tx"
)

// Usecase provides API client management and token issuance.
type Usecase struct {
	clientRepo  apiclient.Repository
	tierRepo    apiclient.TierRepository
	auditRepo   audit.Repository
	txManager   tx.TxManager
	keyRing     KeyRing
	tokenTTL    time.Duration
	serviceName string
}

// NewUsecase constructs an API Auth Usecase.
func NewUsecase(
	clientRepo apiclient.Repository,
	tierRepo apiclient.TierRepository,
	auditRepo audit.Repository,
	txManager tx.TxManager,
	keyRing KeyRing,
	tokenTTL time.Duration,
	serviceName string,
) *Usecase {
	return &Usecase{
		clientRepo:  clientRepo,
		tierRepo:    tierRepo,
		auditRepo:   auditRepo,
		txManager:   txManager,
		keyRing:     keyRing,
		tokenTTL:    tokenTTL,
		serviceName: serviceName,
	}
}
