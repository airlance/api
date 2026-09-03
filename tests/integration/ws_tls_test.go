package integration

import (
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/google/uuid"
	"github.com/gorilla/websocket"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/transport/ws"
)

type mockTicketRepo struct {
	ticket *wsticket.Ticket
}

func (m *mockTicketRepo) Create(ctx context.Context, t *wsticket.Ticket, ttl time.Duration) error {
	m.ticket = t
	return nil
}

func (m *mockTicketRepo) ConsumeByID(ctx context.Context, id string) (*wsticket.Ticket, error) {
	if m.ticket != nil && m.ticket.ID == id {
		t := m.ticket
		m.ticket = nil
		return t, nil
	}
	return nil, wsticket.ErrNotFound
}

type mockSessionRepo struct{}

func (m *mockSessionRepo) Create(ctx context.Context, s *session.Session) error { return nil }
func (m *mockSessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	return &session.Session{ID: id, UserID: uuid.New(), ExpiresAt: time.Now().Add(1 * time.Hour)}, nil
}
func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	return nil, nil
}
func (m *mockSessionRepo) Revoke(ctx context.Context, tokenHash []byte) error { return nil }
func (m *mockSessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockSessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *mockSessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}
func (m *mockSessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockDeviceRepo struct{}

func (m *mockDeviceRepo) Create(ctx context.Context, d *device.Device) error { return nil }
func (m *mockDeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	return &device.Device{ID: id, UserID: uuid.New()}, nil
}
func (m *mockDeviceRepo) GetByHash(ctx context.Context, hash []byte) (*device.Device, error) {
	return nil, nil
}
func (m *mockDeviceRepo) Touch(ctx context.Context, id uuid.UUID, appVer *string, lastSeen time.Time) error {
	return nil
}
func (m *mockDeviceRepo) RebindUser(ctx context.Context, id uuid.UUID, userID uuid.UUID, appVer *string, lastSeen time.Time) error {
	return nil
}
func (m *mockDeviceRepo) UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error {
	return nil
}
func (m *mockDeviceRepo) Revoke(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockDeviceRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	return nil, nil
}

func TestWebSocket_TLS_And_TrustedProxy_Enforcement(t *testing.T) {
	_, trustedCIDR, _ := net.ParseCIDR("10.0.0.1/32")

	cfg := &config.Config{
		RequireTLS:              true,
		TLSTerminationIngress:   true,
		TrustedProxies:          []*net.IPNet{trustedCIDR},
		AllowedWSOrigins:        []string{"https://airlance.org"},
		MaxWSConnections:        100,
		MaxWSConnectionsPerIP:   10,
		MaxWSConnectionsPerUser: 5,
		WSPreUpgradeTimeout:     2 * time.Second,
		WSHandshakeTimeout:      2 * time.Second,
		MaxWSFrameBytes:         64 * 1024,
	}

	ticketRepo := &mockTicketRepo{}
	sessionRepo := &mockSessionRepo{}
	deviceRepo := &mockDeviceRepo{}
	registry := ws.NewConnectionRegistry()
	router := ws.NewRouter(1, 1, nil, nil)
	log := logger.New("error", "json")

	server := ws.NewServer(ticketRepo, sessionRepo, deviceRepo, nil, nil, registry, router, nil, cfg, log)

	ts := httptest.NewServer(server)
	defer ts.Close()

	// 1. Direct plaintext request without TLS -> Should be rejected with 426
	req, _ := http.NewRequest("GET", ts.URL, nil)
	req.Header.Set("Connection", "Upgrade")
	req.Header.Set("Upgrade", "websocket")
	req.Header.Set("Sec-WebSocket-Version", "13")
	req.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}
	if resp.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("expected 426 Upgrade Required for direct plaintext WS, got %d", resp.StatusCode)
	}

	// 2. Untrusted proxy forged X-Forwarded-Proto -> Should still be rejected with 426
	reqUntrusted, _ := http.NewRequest("GET", ts.URL, nil)
	reqUntrusted.Header.Set("Connection", "Upgrade")
	reqUntrusted.Header.Set("Upgrade", "websocket")
	reqUntrusted.Header.Set("Sec-WebSocket-Version", "13")
	reqUntrusted.Header.Set("Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ==")
	reqUntrusted.Header.Set("X-Forwarded-Proto", "https") // Forged by untrusted caller (remote IP is loopback, not 10.0.0.1)

	respUntrusted, err := http.DefaultClient.Do(reqUntrusted)
	if err != nil {
		t.Fatalf("unexpected request error: %v", err)
	}
	if respUntrusted.StatusCode != http.StatusUpgradeRequired {
		t.Errorf("expected 426 for untrusted proxy forwarded proto, got %d", respUntrusted.StatusCode)
	}

	// 3. Origin verification check
	cfgWithLoopbackTrusted := &config.Config{
		RequireTLS:              false, // For testing origin directly
		AllowedWSOrigins:        []string{"https://trusted.airlance.org"},
		MaxWSConnections:        100,
		MaxWSConnectionsPerIP:   10,
		MaxWSConnectionsPerUser: 5,
		WSPreUpgradeTimeout:     2 * time.Second,
		WSHandshakeTimeout:      2 * time.Second,
		MaxWSFrameBytes:         64 * 1024,
	}
	serverWithOrigin := ws.NewServer(ticketRepo, sessionRepo, deviceRepo, nil, nil, registry, router, nil, cfgWithLoopbackTrusted, log)
	tsOrigin := httptest.NewServer(serverWithOrigin)
	defer tsOrigin.Close()

	wsURL := "ws" + strings.TrimPrefix(tsOrigin.URL, "http")
	dialer := websocket.Dialer{}

	// Dial with disallowed origin and valid ticket
	testTicket := &wsticket.Ticket{
		ID:        "origin-test-ticket",
		UserID:    uuid.New(),
		SessionID: uuid.New(),
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}
	_ = ticketRepo.Create(context.Background(), testTicket, 1*time.Minute)

	headerDisallowed := http.Header{}
	headerDisallowed.Set("Origin", "https://malicious.evil.com")
	headerDisallowed.Set("X-WS-Ticket", testTicket.ID)
	_, respOrigin, err := dialer.Dial(wsURL, headerDisallowed)
	if err == nil || respOrigin == nil || respOrigin.StatusCode != http.StatusForbidden {
		t.Errorf("expected 403 Forbidden for disallowed origin, got %v", respOrigin)
	}
}
