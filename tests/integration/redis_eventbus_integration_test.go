package integration

import (
	"context"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/alicebob/miniredis/v2"
	"github.com/google/uuid"
	"github.com/gorilla/websocket"
	goredis "github.com/redis/go-redis/v9"

	"airlance.org/api/internal/config"
	domainEB "airlance.org/api/internal/domain/eventbus"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/eventbus"
	"airlance.org/api/internal/infrastructure/logger"
	"airlance.org/api/internal/transport/ws"
)

func TestRedisEventBus_RealRedisTwoInstanceRevocations(t *testing.T) {
	clientA, clientB := newEventBusRedisClients(t)
	busA := eventbus.NewRedisEventBus(clientA)
	busB := eventbus.NewRedisEventBus(clientB)

	cfg := &config.Config{
		RequireTLS:              false,
		AllowedWSOrigins:        []string{"*"},
		MaxWSConnections:        10,
		MaxWSConnectionsPerIP:   10,
		MaxWSConnectionsPerUser: 5,
		WSPreUpgradeTimeout:     2 * time.Second,
		WSHandshakeTimeout:      2 * time.Second,
		MaxWSFrameBytes:         64 * 1024,
	}

	log := logger.New("error", "json")
	routerB := ws.NewRouter(1, 1)
	registryB := ws.NewConnectionRegistry()
	ticketRepoB := &mockTicketRepo{}
	sessionRepoB := &mockSessionRepo{}
	deviceRepoB := &mockDeviceRepo{}

	serverB := ws.NewServer(ticketRepoB, sessionRepoB, deviceRepoB, nil, nil, registryB, routerB, busB, cfg, log)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	// Start Instance B eventbus listeners connected to Redis B
	if err := serverB.StartEventBusListeners(ctx); err != nil {
		t.Fatalf("failed to start event bus listeners: %v", err)
	}

	time.Sleep(50 * time.Millisecond)

	tsB := httptest.NewServer(serverB)
	defer tsB.Close()

	testUserID := uuid.New()
	testSessionID := uuid.New()
	testTicketID := "remote-redis-revocation-ticket"

	_ = ticketRepoB.Create(context.Background(), &wsticket.Ticket{
		ID:        testTicketID,
		UserID:    testUserID,
		SessionID: testSessionID,
		DeviceID:  new(uuid.New()),
		ExpiresAt: time.Now().Add(1 * time.Minute),
	}, 1*time.Minute)

	wsURL := "ws" + strings.TrimPrefix(tsB.URL, "http") + "?ticket=" + testTicketID
	dialer := websocket.Dialer{}
	conn, _, err := dialer.Dial(wsURL, nil)
	if err != nil {
		t.Fatalf("dial to Instance B failed: %v", err)
	}
	defer conn.Close()

	for i := 0; i < 20 && registryB.Count() == 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if registryB.Count() != 1 {
		t.Fatalf("expected 1 active connection on Instance B, got %d", registryB.Count())
	}

	err = busA.Publish(context.Background(), domainEB.TopicSessionRevoked, domainEB.Event{
		Topic:     domainEB.TopicSessionRevoked,
		Payload:   testSessionID,
		Timestamp: time.Now(),
	})
	if err != nil {
		t.Fatalf("failed to publish revocation from Instance A: %v", err)
	}

	_, _, err = conn.ReadMessage()
	if err == nil {
		t.Fatalf("expected connection to be closed after remote revocation event")
	}

	for i := 0; i < 20 && registryB.Count() > 0; i++ {
		time.Sleep(10 * time.Millisecond)
	}
	if registryB.Count() != 0 {
		t.Errorf("expected registry on Instance B to be empty after revocation, got %d", registryB.Count())
	}
}

func newEventBusRedisClients(t *testing.T) (*goredis.Client, *goredis.Client) {
	t.Helper()

	ctx := context.Background()
	redisURL := os.Getenv("REDIS_URL")
	if redisURL == "" {
		mr, err := miniredis.Run()
		if err != nil {
			t.Fatalf("start miniredis: %v", err)
		}
		t.Cleanup(mr.Close)
		redisURL = "redis://" + mr.Addr() + "/15"
	}

	opts, err := goredis.ParseURL(redisURL)
	if err != nil {
		t.Fatalf("parse Redis URL: %v", err)
	}
	clientA := goredis.NewClient(opts)
	clientB := goredis.NewClient(opts)
	t.Cleanup(func() {
		_ = clientA.Close()
		_ = clientB.Close()
	})

	if err := clientA.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis client A: %v", err)
	}
	if err := clientB.Ping(ctx).Err(); err != nil {
		t.Fatalf("ping Redis client B: %v", err)
	}

	return clientA, clientB
}
