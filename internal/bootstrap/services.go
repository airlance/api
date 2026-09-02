package bootstrap

import (
	"airlance.org/api/internal/config"
	"airlance.org/api/internal/usecase/apiauth"
	"airlance.org/api/internal/usecase/auth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

// Services encapsulates the application use case domain services.
type Services struct {
	Session *sessionUC.Usecase
	Auth    *auth.Usecase
	APIAuth *apiauth.Usecase
}

// InitServices constructs use case services.
func InitServices(cfg *config.Config, infra *Infrastructures, repos *Repositories) *Services {
	sessionService := sessionUC.NewUsecase(
		repos.Session,
		repos.Audit,
		infra.TxManager,
		infra.EventBus,
		cfg.SessionTTL,
	)

	authService := auth.NewUsecase(
		repos.User,
		repos.Identity,
		repos.PasskeyCred,
		repos.Challenge,
		repos.Device,
		repos.Audit,
		sessionService,
		infra.TxManager,
		infra.WebAuthnEngine,
		cfg,
	)

	apiAuthService := apiauth.NewUsecase(
		repos.APIClient,
		repos.RateLimitTier,
		repos.Audit,
		infra.TxManager,
		cfg,
	)

	return &Services{
		Session: sessionService,
		Auth:    authService,
		APIAuth: apiAuthService,
	}
}
