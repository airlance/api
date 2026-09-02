package session

import (
	"time"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/tx"
)

type Usecase struct {
	sessionRepo session.Repository
	auditRepo   audit.Repository
	txManager   tx.TxManager
	eventBus    eventbus.EventBus
	sessionTTL  time.Duration
}

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
