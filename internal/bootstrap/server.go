package bootstrap

import (
	"airlance.org/api/internal/config"
	transportHTTP "airlance.org/api/internal/transport/http"
)

// InitHTTPServer constructs the HTTP Server.
func InitHTTPServer(cfg *config.Config, infra *Infrastructures, services *Services, handlers *Handlers) *transportHTTP.Server {
	return transportHTTP.NewServer(
		handlers.Health,
		handlers.Auth,
		handlers.Ticket,
		handlers.Client,
		handlers.Me,
		handlers.WSServer,
		services.Session,
		infra.Limiter,
		cfg,
		infra.Logger,
	)
}
