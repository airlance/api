package ws

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	"github.com/resoul/wireauth/v2"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/device"
	domainEB "airlance.org/api/internal/domain/eventbus"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/middleware"
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
	clientIP := middleware.GetClientIP(r.Context())
	maskSecret := s.cfg.AuditSubjectHMACKeyRing.Keys[s.cfg.AuditSubjectHMACKeyRing.CurrentKeyID]

	isTLS := r.TLS != nil
	if !isTLS && s.cfg.TLSTerminationIngress {
		if middleware.IsTrustedProxy(r.RemoteAddr, s.cfg.TrustedProxies) {
			forwardedProto := r.Header.Get("X-Forwarded-Proto")
			if strings.EqualFold(forwardedProto, "https") || strings.EqualFold(forwardedProto, "wss") {
				isTLS = true
			}
		}
	}

	if s.cfg.RequireTLS && !isTLS {
		s.log.Warn("Rejected plaintext WebSocket upgrade request", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		http.Error(w, "TLS is mandatory for WebSocket connections", http.StatusUpgradeRequired)
		return
	}

	if s.limiter != nil {
		limits := []domainRL.Limit{
			{Name: "ws_upgrade_burst", Max: 20, Window: 10 * time.Second},
			{Name: "ws_upgrade_min", Max: 60, Window: 1 * time.Minute},
		}
		res, err := s.limiter.Allow(r.Context(), fmt.Sprintf("ws_preupgrade:ip:%s", clientIP), limits)
		if err != nil || (len(res) > 0 && !res[0].Allowed) {
			s.log.Warn("WS pre-upgrade rate limit exceeded or limiter unavailable", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	ticketID := r.Header.Get("X-WS-Ticket")
	if ticketID == "" {
		ticketID = r.URL.Query().Get("ticket")
	}
	if ticketID == "" {
		s.log.Debug("WS upgrade missing ticket")
		http.Error(w, "Missing WebSocket Ticket", http.StatusUnauthorized)
		return
	}

	preCtx, cancelPre := context.WithTimeout(r.Context(), s.cfg.WSPreUpgradeTimeout)
	defer cancelPre()

	ticket, err := s.ticketRepo.ConsumeByID(preCtx, ticketID)
	if err != nil {
		s.log.Warn("Invalid or already consumed WS ticket", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		http.Error(w, "Invalid or Expired Ticket", http.StatusUnauthorized)
		return
	}

	sess, err := s.sessionRepo.GetByID(preCtx, ticket.SessionID)
	if err != nil || sess == nil || !sess.IsValid() {
		s.log.Warn("WS ticket referenced invalid session", "masked_session", logger.MaskUUID(ticket.SessionID, maskSecret))
		http.Error(w, "Session Revoked or Expired", http.StatusUnauthorized)
		return
	}

	if ticket.DeviceID != nil {
		dev, err := s.deviceRepo.GetByID(preCtx, *ticket.DeviceID)
		if err != nil || dev == nil || !dev.IsValid() {
			s.log.Warn("WS ticket referenced invalid device", "masked_device", logger.MaskUUID(*ticket.DeviceID, maskSecret))
			http.Error(w, "Device Revoked", http.StatusUnauthorized)
			return
		}
	}

	if s.registry.Count() >= s.cfg.MaxWSConnections {
		s.log.Warn("Max server WebSocket connections reached", "count", s.registry.Count())
		http.Error(w, "Server Busy", http.StatusServiceUnavailable)
		return
	}

	userConns := s.registry.ForUser(ticket.UserID)
	if len(userConns) >= s.cfg.MaxWSConnectionsPerUser {
		s.log.Warn("Max per-user WebSocket connections reached", "masked_user", logger.MaskUUID(ticket.UserID, maskSecret))
		http.Error(w, "Too Many Connections for User", http.StatusTooManyRequests)
		return
	}

	if s.registry.CountForIP(clientIP) >= s.cfg.MaxWSConnectionsPerIP {
		s.log.Warn("Max per-IP WebSocket connections reached", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		http.Error(w, "Too Many Connections for IP", http.StatusTooManyRequests)
		return
	}

	wsConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Error(err, "WebSocket upgrade failed", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		return
	}

	var c2sKey, s2cKey []byte
	if s.wireauthServer != nil {
		_ = wsConn.SetReadDeadline(time.Now().Add(s.cfg.WSHandshakeTimeout))
		_ = wsConn.SetWriteDeadline(time.Now().Add(s.cfg.WSHandshakeTimeout))

		handshakeCtx, cancelHandshake := context.WithTimeout(r.Context(), s.cfg.WSHandshakeTimeout)
		defer cancelHandshake()

		wireauthSession, err := s.wireauthServer.Perform(handshakeCtx, wsConn)
		if err != nil {
			s.log.Warn("Wireauth v2 handshake failed", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
			_ = wsConn.Close()
			return
		}
		c2sKey = wireauthSession.ClientToServerKey
		s2cKey = wireauthSession.ServerToClientKey

		_ = wsConn.SetReadDeadline(time.Time{})
		_ = wsConn.SetWriteDeadline(time.Time{})
	} else {
		c2sKey = make([]byte, 32)
		s2cKey = make([]byte, 32)
	}

	wsSession := NewSession(
		r.Context(),
		wsConn,
		ticket.UserID,
		ticket.SessionID,
		ticket.DeviceID,
		clientIP,
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

	s.log.Info("WS connection established", "masked_user", logger.MaskUUID(ticket.UserID, maskSecret), "masked_session", logger.MaskUUID(ticket.SessionID, maskSecret))
	wsSession.StartLifecycle()
}

func (s *Server) Shutdown(ctx context.Context) error {
	s.log.Info("Draining WebSocket connections")
	s.registry.Drain(2 * time.Second)
	return nil
}

func (s *Server) StartEventBusListeners(ctx context.Context) error {
	if s.eventBus == nil {
		return nil
	}

	sessionSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicSessionRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe session.revoked error: %w", err)
	}

	deviceSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicDeviceRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe device.revoked error: %w", err)
	}

	userSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicUserSessionsRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe user.sessions_revoked error: %w", err)
	}

	go s.listenRevocationEvents(ctx, sessionSub, func(payload any) {
		if sid, ok := extractUUID(payload); ok {
			for _, conn := range s.registry.ForSession(sid) {
				conn.Close("session_revoked")
			}
		}
	})

	go s.listenRevocationEvents(ctx, deviceSub, func(payload any) {
		if did, ok := extractUUID(payload); ok {
			for _, conn := range s.registry.ForDevice(did) {
				conn.Close("device_revoked")
			}
		}
	})

	go s.listenRevocationEvents(ctx, userSub, func(payload any) {
		if uid, ok := extractUUID(payload); ok {
			for _, conn := range s.registry.ForUser(uid) {
				conn.Close("user_sessions_revoked")
			}
		}
	})

	return nil
}

func extractUUID(payload any) (uuid.UUID, bool) {
	switch v := payload.(type) {
	case uuid.UUID:
		return v, true
	case string:
		id, err := uuid.Parse(v)
		return id, err == nil
	default:
		return uuid.Nil, false
	}
}

func (s *Server) listenRevocationEvents(ctx context.Context, sub domainEB.Subscription, handler func(payload any)) {
	defer sub.Close()
	for {
		select {
		case <-ctx.Done():
			return
		case ev, ok := <-sub.Events():
			if !ok {
				return
			}
			handler(ev.Payload)
		}
	}
}
