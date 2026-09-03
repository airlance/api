package ws

import (
	"context"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/gorilla/websocket"

	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/middleware"
)

type preUpgradeResult struct {
	ticket   *wsticket.Ticket
	clientIP string
}

func (s *Server) validatePreUpgrade(w http.ResponseWriter, r *http.Request) (*preUpgradeResult, bool) {
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
		return nil, false
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
			return nil, false
		}
	}

	ticketID := r.Header.Get("X-WS-Ticket")
	if ticketID == "" {
		ticketID = r.URL.Query().Get("ticket")
	}
	if ticketID == "" {
		s.log.Debug("WS upgrade missing ticket")
		http.Error(w, "Missing WebSocket Ticket", http.StatusUnauthorized)
		return nil, false
	}

	preCtx, cancelPre := context.WithTimeout(r.Context(), s.cfg.WSPreUpgradeTimeout)
	defer cancelPre()

	ticket, err := s.ticketRepo.ConsumeByID(preCtx, ticketID)
	if err != nil {
		s.log.Warn("Invalid or already consumed WS ticket", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		http.Error(w, "Invalid or Expired Ticket", http.StatusUnauthorized)
		return nil, false
	}

	sess, err := s.sessionRepo.GetByID(preCtx, ticket.SessionID)
	if err != nil || sess == nil || !sess.IsValid() {
		s.log.Warn("WS ticket referenced invalid session", "masked_session", logger.MaskUUID(ticket.SessionID, maskSecret))
		http.Error(w, "Session Revoked or Expired", http.StatusUnauthorized)
		return nil, false
	}

	if ticket.DeviceID != nil {
		dev, err := s.deviceRepo.GetByID(preCtx, *ticket.DeviceID)
		if err != nil || dev == nil || !dev.IsValid() {
			s.log.Warn("WS ticket referenced invalid device", "masked_device", logger.MaskUUID(*ticket.DeviceID, maskSecret))
			http.Error(w, "Device Revoked", http.StatusUnauthorized)
			return nil, false
		}
	}

	if s.registry.Count() >= s.cfg.MaxWSConnections {
		s.log.Warn("Max server WebSocket connections reached", "count", s.registry.Count())
		http.Error(w, "Server Busy", http.StatusServiceUnavailable)
		return nil, false
	}

	userConns := s.registry.ForUser(ticket.UserID)
	if len(userConns) >= s.cfg.MaxWSConnectionsPerUser {
		s.log.Warn("Max per-user WebSocket connections reached", "masked_user", logger.MaskUUID(ticket.UserID, maskSecret))
		http.Error(w, "Too Many Connections for User", http.StatusTooManyRequests)
		return nil, false
	}

	if s.registry.CountForIP(clientIP) >= s.cfg.MaxWSConnectionsPerIP {
		s.log.Warn("Max per-IP WebSocket connections reached", "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		http.Error(w, "Too Many Connections for IP", http.StatusTooManyRequests)
		return nil, false
	}

	return &preUpgradeResult{
		ticket:   ticket,
		clientIP: clientIP,
	}, true
}

func (s *Server) performHandshake(ctx context.Context, wsConn *websocket.Conn, clientIP string, maskSecret []byte) (c2sKey, s2cKey []byte, err error) {
	if s.wireauthServer == nil {
		_ = wsConn.Close()
		return nil, nil, fmt.Errorf("wireauth: server not initialised — refusing connection to prevent insecure zero-key fallback")
	}

	_ = wsConn.SetReadDeadline(time.Now().Add(s.cfg.WSHandshakeTimeout))
	_ = wsConn.SetWriteDeadline(time.Now().Add(s.cfg.WSHandshakeTimeout))

	handshakeCtx, cancelHandshake := context.WithTimeout(ctx, s.cfg.WSHandshakeTimeout)
	defer cancelHandshake()

	wireauthSession, err := s.wireauthServer.Perform(handshakeCtx, wsConn)
	if err != nil {
		s.log.Warn("Wireauth v2 handshake failed", "error", err, "masked_ip", logger.MaskIdentifier(clientIP, maskSecret))
		_ = wsConn.Close()
		return nil, nil, err
	}

	_ = wsConn.SetReadDeadline(time.Time{})
	_ = wsConn.SetWriteDeadline(time.Time{})

	return wireauthSession.ClientToServerKey, wireauthSession.ServerToClientKey, nil
}
