package bootstrap

import (
	"airlance.org/api/internal/config"
	transportHTTP "airlance.org/api/internal/transport/http"
	v1 "airlance.org/api/internal/transport/http/v1"
	"airlance.org/api/internal/transport/ws"
)

type Handlers struct {
	Health     *transportHTTP.HealthHandlers
	Auth       *v1.AuthHandlers
	Device     *v1.DeviceHandlers
	Ticket     *v1.TicketHandlers
	Client     *v1.ClientHandlers
	Me         *v1.MeHandlers
	WSRegistry ws.ConnectionRegistry
	WSRouter   *ws.Router
	WSServer   *ws.Server
}

func InitHandlers(cfg *config.Config, infra *Infrastructures, repos *Repositories, services *Services) *Handlers {
	health := transportHTTP.NewHealthHandlers(infra.DBPool, infra.RedisClient, cfg)
	authHandlers := v1.NewAuthHandlers(services.Auth, services.Session, cfg)
	deviceHandlers := v1.NewDeviceHandlers(services.Auth)
	ticketHandlers := v1.NewTicketHandlers(repos.WSTicket, cfg)
	clientHandlers := v1.NewClientHandlers(services.APIAuth)
	meHandlers := v1.NewMeHandlers(infra.Limiter)

	wsRegistry := ws.NewConnectionRegistry()
	wsRouter := ws.NewRouter(cfg.MinSupportedProtocol, cfg.CurrentProtocol)
	wsServer := ws.NewServer(
		repos.WSTicket,
		repos.Session,
		repos.Device,
		infra.Limiter,
		infra.WireauthServer,
		wsRegistry,
		wsRouter,
		infra.EventBus,
		cfg,
		infra.Logger,
	)

	return &Handlers{
		Health:     health,
		Auth:       authHandlers,
		Device:     deviceHandlers,
		Ticket:     ticketHandlers,
		Client:     clientHandlers,
		Me:         meHandlers,
		WSRegistry: wsRegistry,
		WSRouter:   wsRouter,
		WSServer:   wsServer,
	}
}
