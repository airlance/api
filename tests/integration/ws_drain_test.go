package integration

import (
	"context"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/transport/ws"
)

func TestWebSocket_GracefulDrainingShutdown(t *testing.T) {
	cfg := &config.Config{
		RequireTLS:              false,
		AllowedWSOrigins:        []string{"*"},
		MaxWSConnections:        10,
		MaxWSConnectionsPerIP:   10,
		MaxWSConnectionsPerUser: 5,
		WSPreUpgradeTimeout:     2 * time.Second,
		WSHandshakeTimeout:      2 * time.Second,
		MaxWSFrameBytes:         64 * 1024,
		AuditSubjectHMACKeyRing: config.KeyRing{
			CurrentKeyID: 1,
			Keys:         map[uint16][]byte{1: []byte("01234567890123456789012345678901")},
		},
	}

	ticketRepo := &mockTicketRepo{}
	sessionRepo := &mockSessionRepo{}
	deviceRepo := &mockDeviceRepo{}
	registry := ws.NewConnectionRegistry()
	router := ws.NewRouter(1, 1)
	log := logger.New("error", "json")

	server := ws.NewServer(ticketRepo, sessionRepo, deviceRepo, nil, nil, registry, router, nil, cfg, log)

	ts := httptest.NewServer(server)
	defer ts.Close()

	// 1. Issue ticket & connect
	ticketID := "test-drain-ticket"
	_ = ticketRepo.Create(context.Background(), &wsticket.Ticket{
		ID:        ticketID,
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}, 1*time.Minute)

	wsURL := "ws" + strings.TrimPrefix(ts.URL, "http") + "?ticket=" + ticketID
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial failed: %v", err)
	}
	defer conn.Close()

	// Wait briefly for registration to settle
	for i := 0; i < 20 && registry.Count() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}

	if registry.Count() != 1 {
		t.Errorf("expected 1 active connection, got %d", registry.Count())
	}

	// 2. Trigger graceful drain
	go func() {
		time.Sleep(50 * time.Millisecond)
		_ = server.Shutdown(context.Background())
	}()

	// 3. Read message on client - expect CloseGoingAway (1001)
	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatalf("expected close error")
	}

	if !websocket.IsCloseError(err, websocket.CloseGoingAway, websocket.CloseNormalClosure) {
		t.Errorf("expected CloseGoingAway (1001), got %v", err)
	}
}
