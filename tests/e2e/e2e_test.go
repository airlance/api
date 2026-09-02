package e2e

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
	domainRL "airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/wsticket"
	"airlance.org/api/internal/infrastructure/logger"
	transportHTTP "airlance.org/api/internal/transport/http"
	v1 "airlance.org/api/internal/transport/http/v1"
	"airlance.org/api/internal/usecase/apiauth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type inMemorySessionRepo struct {
	sessions map[string]*session.Session
}

func (m *inMemorySessionRepo) Create(ctx context.Context, s *session.Session) error {
	m.sessions[string(s.TokenHash)] = s
	return nil
}
func (m *inMemorySessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	s, ok := m.sessions[string(tokenHash)]
	if !ok || s.RevokedAt != nil || time.Now().After(s.ExpiresAt) {
		return nil, session.ErrNotFound
	}
	return s, nil
}
func (m *inMemorySessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, session.ErrNotFound
}
func (m *inMemorySessionRepo) Revoke(ctx context.Context, tokenHash []byte) error { return nil }
func (m *inMemorySessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error { return nil }
func (m *inMemorySessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (m *inMemorySessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}
func (m *inMemorySessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type inMemoryClientRepo struct {
	clients map[uuid.UUID]*apiclient.APIClient
}

func (m *inMemoryClientRepo) Create(ctx context.Context, c *apiclient.APIClient) error {
	m.clients[c.ID] = c
	return nil
}
func (m *inMemoryClientRepo) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.APIClient, error) {
	c, ok := m.clients[id]
	if !ok {
		return nil, apiclient.ErrClientNotFound
	}
	return c, nil
}
func (m *inMemoryClientRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*apiclient.APIClient, error) {
	var res []*apiclient.APIClient
	for _, c := range m.clients {
		if c.UserID == userID {
			res = append(res, c)
		}
	}
	return res, nil
}
func (m *inMemoryClientRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	if c, ok := m.clients[id]; ok {
		now := time.Now()
		c.RevokedAt = &now
		return nil
	}
	return apiclient.ErrClientNotFound
}

type inMemoryTierRepo struct {
	tier *apiclient.RateLimitTier
}

func (m *inMemoryTierRepo) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.RateLimitTier, error) {
	return m.tier, nil
}
func (m *inMemoryTierRepo) GetByName(ctx context.Context, name string) (*apiclient.RateLimitTier, error) {
	return m.tier, nil
}

type inMemoryTicketRepo struct {
	tickets map[string]*wsticket.Ticket
}

func (m *inMemoryTicketRepo) Create(ctx context.Context, ticket *wsticket.Ticket, ttl time.Duration) error {
	m.tickets[ticket.ID] = ticket
	return nil
}
func (m *inMemoryTicketRepo) ConsumeByID(ctx context.Context, id string) (*wsticket.Ticket, error) {
	t, ok := m.tickets[id]
	if !ok {
		return nil, wsticket.ErrNotFound
	}
	delete(m.tickets, id)
	return t, nil
}

type inMemoryLimiter struct {
	counts map[string]int64
}

func (m *inMemoryLimiter) Allow(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
	res := make([]domainRL.Result, len(limits))
	allAllowed := true
	for i, l := range limits {
		k := key + ":" + l.Name
		m.counts[k]++
		cur := m.counts[k]
		allowed := cur <= l.Max
		if !allowed {
			allAllowed = false
		}
		rem := l.Max - cur
		if rem < 0 {
			rem = 0
		}
		res[i] = domainRL.Result{
			Allowed:    allowed,
			Remaining:  rem,
			ResetAt:    time.Now().Add(l.Window),
			RetryAfter: l.Window,
		}
	}
	for i := range res {
		res[i].Allowed = allAllowed
	}
	return res, nil
}

func (m *inMemoryLimiter) Usage(ctx context.Context, key string, limits []domainRL.Limit) ([]domainRL.Result, error) {
	res := make([]domainRL.Result, len(limits))
	for i, l := range limits {
		k := key + ":" + l.Name
		cur := m.counts[k]
		rem := l.Max - cur
		if rem < 0 {
			rem = 0
		}
		res[i] = domainRL.Result{
			Allowed:    cur < l.Max,
			Remaining:  rem,
			ResetAt:    time.Now().Add(l.Window),
			RetryAfter: l.Window,
		}
	}
	return res, nil
}

type noopAuditRepo struct{}

func (n *noopAuditRepo) Record(ctx context.Context, e *audit.Event) error { return nil }

type noopTxManager struct{}

func (n *noopTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

func TestE2E_FullFlow(t *testing.T) {
	seed := []byte("01234567890123456789012345678901")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	cfg := &config.Config{
		ServiceName:      "airlance-api",
		APITokenTTL:      15 * time.Minute,
		WSTicketTTL:      30 * time.Second,
		MaxHTTPBodyBytes: 2 * 1024 * 1024,
		JWTKeyRing: config.Ed25519KeyRing{
			CurrentKID:  "key-1",
			PrivateKeys: map[string]ed25519.PrivateKey{"key-1": priv},
			PublicKeys:  map[string]ed25519.PublicKey{"key-1": pub},
		},
	}

	sessionRepo := &inMemorySessionRepo{sessions: make(map[string]*session.Session)}
	clientRepo := &inMemoryClientRepo{clients: make(map[uuid.UUID]*apiclient.APIClient)}
	tierRepo := &inMemoryTierRepo{
		tier: &apiclient.RateLimitTier{
			ID:                uuid.New(),
			Name:              "default",
			RequestsPerMinute: 2, // Low for easy 429 testing
			RequestsPerDay:    100,
		},
	}
	ticketRepo := &inMemoryTicketRepo{tickets: make(map[string]*wsticket.Ticket)}
	limiter := &inMemoryLimiter{counts: make(map[string]int64)}
	auditRepo := &noopAuditRepo{}
	txManager := &noopTxManager{}
	log := logger.New("error", "json")

	sessionUCInstance := sessionUC.NewUsecase(sessionRepo, auditRepo, txManager, nil, 24*time.Hour)
	apiKeyRing := apiauth.KeyRing{
		CurrentKID:  cfg.JWTKeyRing.CurrentKID,
		PrivateKeys: cfg.JWTKeyRing.PrivateKeys,
	}
	apiAuthUCInstance := apiauth.NewUsecase(clientRepo, tierRepo, auditRepo, txManager, apiKeyRing, cfg.APITokenTTL, cfg.ServiceName)

	healthHandlers := transportHTTP.NewHealthHandlers(nil, nil, cfg)
	ticketHandlers := v1.NewTicketHandlers(ticketRepo, cfg)
	clientHandlers := v1.NewClientHandlers(apiAuthUCInstance)
	meHandlers := v1.NewMeHandlers(limiter)

	server := transportHTTP.NewServer(
		healthHandlers,
		&v1.AuthHandlers{},
		nil,
		ticketHandlers,
		clientHandlers,
		meHandlers,
		nil,
		sessionUCInstance,
		limiter,
		nil,
		cfg,
		log,
	)

	ts := httptest.NewServer(server.Handler())
	defer ts.Close()

	// 1. Check /livez and /readyz
	resp, err := http.Get(ts.URL + "/livez")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("livez failed: code=%v, err=%v", resp.StatusCode, err)
	}

	resp, err = http.Get(ts.URL + "/readyz")
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("readyz failed: code=%v, err=%v", resp.StatusCode, err)
	}

	// 2. Setup authenticated session
	userID := uuid.New()
	identID := uuid.New()
	sessionToken, _, err := sessionUCInstance.CreateSession(context.Background(), userID, identID, nil, "127.0.0.1", "test", "req-1")
	if err != nil {
		t.Fatalf("create session failed: %v", err)
	}

	// 3. Request WS Ticket
	req, _ := http.NewRequest("POST", ts.URL+"/api/v1/ws/ticket", nil)
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("ticket creation failed: code=%v, err=%v", resp.StatusCode, err)
	}
	var ticketData map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&ticketData)
	if ticketData["ticket"] == nil || ticketData["ticket"] == "" {
		t.Fatalf("expected valid ticket string")
	}

	// 4. Create API Client
	createBody, _ := json.Marshal(map[string]string{"name": "E2E Client"})
	req, _ = http.NewRequest("POST", ts.URL+"/api/v1/clients", bytes.NewReader(createBody))
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusCreated {
		var errBody map[string]any
		_ = json.NewDecoder(resp.Body).Decode(&errBody)
		t.Fatalf("client creation failed: code=%v, err=%v, body=%v", resp.StatusCode, err, errBody)
	}
	var clientRes struct {
		Client *apiclient.APIClient `json:"client"`
		Secret string               `json:"secret"`
	}
	_ = json.NewDecoder(resp.Body).Decode(&clientRes)
	if clientRes.Client == nil || clientRes.Secret == "" {
		t.Fatalf("expected created client and secret")
	}

	// 5. Issue API Client JWT
	tokenReqBody, _ := json.Marshal(map[string]string{
		"client_id": clientRes.Client.ID.String(),
		"secret":    clientRes.Secret,
	})
	resp, err = http.Post(ts.URL+"/api/v1/auth/token", "application/json", bytes.NewReader(tokenReqBody))
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("token issuance failed: code=%v, err=%v", resp.StatusCode, err)
	}
	var tokenRes map[string]any
	_ = json.NewDecoder(resp.Body).Decode(&tokenRes)
	jwtToken := tokenRes["access_token"].(string)

	// 6. Access /api/v1/getMe (First Request: Success)
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/getMe", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("getMe request 1 failed: code=%v, err=%v", resp.StatusCode, err)
	}

	// 7. Access /api/v1/getMe (Second Request: Success, at limit 2)
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/getMe", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("getMe request 2 failed: code=%v, err=%v", resp.StatusCode, err)
	}

	// 8. Access /api/v1/getMe (Third Request: 429 Rate Limited!)
	req, _ = http.NewRequest("GET", ts.URL+"/api/v1/getMe", nil)
	req.Header.Set("Authorization", "Bearer "+jwtToken)
	resp, err = http.DefaultClient.Do(req)
	if err != nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("expected 429 Too Many Requests on request 3, got: %v", resp.StatusCode)
	}
	if resp.Header.Get("Retry-After") == "" {
		t.Errorf("expected Retry-After header on 429 response")
	}
}
