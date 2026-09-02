package session

import (
	"time"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/tx"
)

// Usecase defines session management operations.
type Usecase struct {
	sessionRepo session.Repository
	auditRepo   audit.Repository
	txManager   tx.TxManager
	eventBus    eventbus.EventBus
	sessionTTL  time.Duration
}

// NewUsecase constructs a Session Usecase.
func NewUsecase(
	sessionRepo session.Repository,
	auditRepo audit.Repository,
	txManager tx.TxManager,
	eventBus eventbus.EventBus,
	sessionTTL time.Duration,
) *Usecase {
	return &Usecase{
		sessionRepo: sessionRepo,
		auditRepo:   auditRepo,
		txManager:   txManager,
		eventBus:    eventBus,
		sessionTTL:  sessionTTL,
	}
}
