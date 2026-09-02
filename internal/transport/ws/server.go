package ws

import (
	"context"
	"fmt"
	"net/http"
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

// Server coordinates WebSocket upgrade requests, ticket validation, and wireauth handshakes.
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

// NewServer constructs a WebSocket Server.
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
	return &Server{
		upgrader: websocket.Upgrader{
			ReadBufferSize:  int(cfg.MaxWSFrameBytes),
			WriteBufferSize: int(cfg.MaxWSFrameBytes),
			CheckOrigin: func(r *http.Request) bool {
				return true // Cross-origin checked via ticket
			},
		},
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
}

// ServeHTTP handles the /ws upgrade endpoint.
func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	clientIP := middleware.GetClientIP(r.Context())

	// 1. Pre-upgrade IP rate limiting (fail-closed to protect from DoS)
	if s.limiter != nil {
		limits := []domainRL.Limit{
			{Name: "ws_upgrade_burst", Max: 20, Window: 10 * time.Second},
			{Name: "ws_upgrade_min", Max: 60, Window: 1 * time.Minute},
		}
		res, err := s.limiter.Allow(r.Context(), fmt.Sprintf("ws_preupgrade:ip:%s", clientIP), limits)
		if err != nil || (len(res) > 0 && !res[0].Allowed) {
			s.log.Warn("WS pre-upgrade rate limit exceeded or limiter unavailable", "ip", clientIP)
			http.Error(w, "Too Many Requests", http.StatusTooManyRequests)
			return
		}
	}

	// 2. Extract ticket
	ticketID := r.Header.Get("X-WS-Ticket")
	if ticketID == "" {
		ticketID = r.URL.Query().Get("ticket")
	}
	if ticketID == "" {
		s.log.Debug("WS upgrade missing ticket", "ip", clientIP)
		http.Error(w, "Missing WebSocket Ticket", http.StatusUnauthorized)
		return
	}

	// 3. Atomically consume ticket (DELETE ... RETURNING in Redis)
	ticket, err := s.ticketRepo.ConsumeByID(r.Context(), ticketID)
	if err != nil {
		s.log.Warn("Invalid or already consumed WS ticket", "ip", clientIP, "err", err)
		http.Error(w, "Invalid or Expired Ticket", http.StatusUnauthorized)
		return
	}

	// 4. Validate underlying session and device state before handshake
	sess, err := s.sessionRepo.GetByID(r.Context(), ticket.SessionID)
	if err != nil || sess == nil || !sess.IsValid() {
		s.log.Warn("WS ticket referenced invalid session", "session_id", ticket.SessionID.String())
		http.Error(w, "Session Revoked or Expired", http.StatusUnauthorized)
		return
	}

	if ticket.DeviceID != nil {
		dev, err := s.deviceRepo.GetByID(r.Context(), *ticket.DeviceID)
		if err != nil || dev == nil || !dev.IsValid() {
			s.log.Warn("WS ticket referenced invalid device", "device_id", ticket.DeviceID.String())
			http.Error(w, "Device Revoked", http.StatusUnauthorized)
			return
		}
	}

	// 5. Connection limits check
	if s.registry.Count() >= s.cfg.MaxWSConnections {
		s.log.Warn("Max server WebSocket connections reached", "count", s.registry.Count())
		http.Error(w, "Server Busy", http.StatusServiceUnavailable)
		return
	}

	userConns := s.registry.ForUser(ticket.UserID)
	if len(userConns) >= s.cfg.MaxWSConnectionsPerUser {
		s.log.Warn("Max per-user WebSocket connections reached", "user_id", ticket.UserID.String())
		http.Error(w, "Too Many Connections for User", http.StatusTooManyRequests)
		return
	}

	// 6. Upgrade connection to WebSocket
	wsConn, err := s.upgrader.Upgrade(w, r, nil)
	if err != nil {
		s.log.Error(err, "WebSocket upgrade failed", "ip", clientIP)
		return
	}

	// 7. Perform Wireauth v2 handshake
	_ = wsConn.SetReadDeadline(time.Now().Add(s.cfg.WSHandshakeTimeout))
	_ = wsConn.SetWriteDeadline(time.Now().Add(s.cfg.WSHandshakeTimeout))

	handshakeCtx, cancelHandshake := context.WithTimeout(r.Context(), s.cfg.WSHandshakeTimeout)
	defer cancelHandshake()

	wireauthSession, err := s.wireauthServer.Perform(handshakeCtx, wsConn)
	if err != nil {
		s.log.Warn("Wireauth v2 handshake failed", "ip", clientIP, "err", err)
		_ = wsConn.Close()
		return
	}

	// Reset deadlines for normal transport
	_ = wsConn.SetReadDeadline(time.Time{})
	_ = wsConn.SetWriteDeadline(time.Time{})

	// 8. Construct session and start lifecycle loops
	wsSession := NewSession(
		r.Context(),
		wsConn,
		ticket.UserID,
		ticket.SessionID,
		ticket.DeviceID,
		wireauthSession.ClientToServerKey,
		wireauthSession.ServerToClientKey,
		s.registry,
		s.router,
		s.cfg,
		s.log,
	)

	s.log.Info("WS connection established", "user_id", ticket.UserID.String(), "session_id", ticket.SessionID.String())
	wsSession.StartLifecycle()
}

// StartEventBusListeners listens for session revocation events to terminate active WS channels.
func (s *Server) StartEventBusListeners(ctx context.Context) error {
	if s.eventBus == nil {
		return nil
	}

	// Listen for session.revoked
	sessionSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicSessionRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe session.revoked error: %w", err)
	}

	// Listen for device.revoked
	deviceSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicDeviceRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe device.revoked error: %w", err)
	}

	// Listen for user.sessions_revoked
	userSub, err := s.eventBus.Subscribe(ctx, domainEB.TopicUserSessionsRevoked)
	if err != nil {
		return fmt.Errorf("ws server: subscribe user.sessions_revoked error: %w", err)
	}

	go s.listenRevocationEvents(ctx, sessionSub, func(payload any) {
		if sid, ok := payload.(uuid.UUID); ok {
			for _, conn := range s.registry.ForSession(sid) {
				conn.Close("session_revoked")
			}
		}
	})

	go s.listenRevocationEvents(ctx, deviceSub, func(payload any) {
		if did, ok := payload.(uuid.UUID); ok {
			for _, conn := range s.registry.ForDevice(did) {
				conn.Close("device_revoked")
			}
		}
	})

	go s.listenRevocationEvents(ctx, userSub, func(payload any) {
		if uid, ok := payload.(uuid.UUID); ok {
			for _, conn := range s.registry.ForUser(uid) {
				conn.Close("user_sessions_revoked")
			}
		}
	})

	return nil
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
