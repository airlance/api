package ws

import (
	"context"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"
	"github.com/resoul/wireauth/v2"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/device"
	domainEB "airlance.org/api/internal/domain/eventbus"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
)

type Server struct {
	upgrader       websocket.Upgrader
	ticketRepo     wsticket.Repository
	sessionRepo    session.Repository
	deviceRepo     device.Repository
	limiter        domainRL.Limiter
	wireauthServer *wireauth.Server
	registry       ConnectionRegistry
	router         *Router
	eventBus       domainEB.EventBus
	cfg            *config.Config
	log            *logger.Logger
}

func NewServer(
	ticketRepo wsticket.Repository,
	sessionRepo session.Repository,
	deviceRepo device.Repository,
	limiter domainRL.Limiter,
	wireauthServer *wireauth.Server,
	registry ConnectionRegistry,
	router *Router,
	eventBus domainEB.EventBus,
	cfg *config.Config,
	log *logger.Logger,
) *Server {
	s := &Server{
		ticketRepo:     ticketRepo,
		sessionRepo:    sessionRepo,
		deviceRepo:     deviceRepo,
		limiter:        limiter,
		wireauthServer: wireauthServer,
		registry:       registry,
		router:         router,
		eventBus:       eventBus,
		cfg:            cfg,
		log:            log.Named(logger.CategoryWS),
	}

	allowedOrigins := cfg.AllowedWSOrigins
	if len(allowedOrigins) == 0 {
		allowedOrigins = cfg.WebAuthnRPOrigins
	}

	s.upgrader = websocket.Upgrader{
		ReadBufferSize:  int(cfg.MaxWSFrameBytes),
		WriteBufferSize: int(cfg.MaxWSFrameBytes),
		CheckOrigin: func(r *http.Request) bool {
			origin := r.Header.Get("Origin")
			if origin == "" {
				// Non-browser client
				return true
			}
			for _, allowed := range allowedOrigins {
				if strings.EqualFold(origin, allowed) || allowed == "*" {
					return true
				}
			}
			s.log.Warn("Rejected WebSocket upgrade due to unauthorized origin", "origin", origin)
			return false
		},
	}

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	pre, ok := s.validatePreUpgrade(w, r)
	if !ok {
		return
	}

	maskSecret := s.cfg.AuditSubjectHMACKeyRing.Keys[s.cfg.AuditSubjectHMACKeyRing.CurrentKeyID]

	wsConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Error(err, "WebSocket upgrade failed", "masked_ip", logger.MaskIdentifier(pre.clientIP, maskSecret))
		return
	}

	c2sKey, s2cKey, err := s.performHandshake(r.Context(), wsConn, pre.clientIP, maskSecret)
	if err != nil {
		return
	}

	wsSession := NewSession(
		r.Context(),
		wsConn,
		pre.ticket.UserID,
		pre.ticket.SessionID,
		pre.ticket.DeviceID,
		pre.clientIP,
		c2sKey,
		s2cKey,
		s.registry,
		s.router,
		s.cfg,
		s.log,
	)

	if err := s.registry.TryRegister(wsSession, s.cfg.MaxWSConnections, s.cfg.MaxWSConnectionsPerUser, s.cfg.MaxWSConnectionsPerIP); err != nil {
		s.log.Warn("WebSocket registration failed limit check", "err", err)
		wsSession.Close("connection_limit_reached")
		return
	}

	s.log.Info("WS connection established", "masked_user", logger.MaskUUID(pre.ticket.UserID, maskSecret), "masked_session", logger.MaskUUID(pre.ticket.SessionID, maskSecret))
	wsSession.StartLifecycle()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("Draining WebSocket connections")
	s.registry.Drain(2 * time.Second)
	return nil
}
