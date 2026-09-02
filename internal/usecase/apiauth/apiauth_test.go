package apiauth

import (
	"context"
	"crypto/ed25519"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
)

type mockClientRepo struct {
	clients map[uuid.UUID]*apiclient.APIClient
}

func newMockClientRepo() *mockClientRepo {
	return &mockClientRepo{clients: make(map[uuid.UUID]*apiclient.APIClient)}
}

func (m *mockClientRepo) Create(ctx context.Context, c *apiclient.APIClient) error {
	m.clients[c.ID] = c
	return nil
}

func (m *mockClientRepo) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.APIClient, error) {
	c, ok := m.clients[id]
	if !ok {
		return nil, apiclient.ErrClientNotFound
	}
	return c, nil
}

func (m *mockClientRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*apiclient.APIClient, error) {
	var res []*apiclient.APIClient
	for _, c := range m.clients {
		if c.UserID == userID {
			res = append(res, c)
		}
	}
	return res, nil
}

func (m *mockClientRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	c, ok := m.clients[id]
	if !ok {
		return apiclient.ErrClientNotFound
	}
	now := time.Now()
	c.RevokedAt = &now
	return nil
}

type mockTierRepo struct {
	tiers map[string]*apiclient.RateLimitTier
}

func newMockTierRepo() *mockTierRepo {
	return &mockTierRepo{
		tiers: map[string]*apiclient.RateLimitTier{
			"default": {
				ID:                uuid.MustParse("00000000-0000-0000-0000-000000000001"),
				Name:              "default",
				RequestsPerMinute: 60,
				RequestsPerDay:    5000,
			},
		},
	}
}

func (m *mockTierRepo) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.RateLimitTier, error) {
	for _, t := range m.tiers {
		if t.ID == id {
			return t, nil
		}
	}
	return nil, apiclient.ErrTierNotFound
}

func (m *mockTierRepo) GetByName(ctx context.Context, name string) (*apiclient.RateLimitTier, error) {
	t, ok := m.tiers[name]
	if !ok {
		return nil, apiclient.ErrTierNotFound
	}
	return t, nil
}

type mockTxManager struct{}

func (m *mockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type mockAuditRepo struct {
	events []*audit.Event
}

func (m *mockAuditRepo) Record(ctx context.Context, e *audit.Event) error {
	m.events = append(m.events, e)
	return nil
}

func TestAPIAuthUsecase_CreateClientAndIssueToken(t *testing.T) {
	clientRepo := newMockClientRepo()
	tierRepo := newMockTierRepo()
	auditRepo := &mockAuditRepo{}
	txManager := &mockTxManager{}

	seed := []byte("01234567890123456789012345678901")
	priv := ed25519.NewKeyFromSeed(seed)

	keyRing := KeyRing{
		CurrentKID:  "key-1",
		PrivateKeys: map[string]ed25519.PrivateKey{"key-1": priv},
	}

	uc := NewUsecase(clientRepo, tierRepo, auditRepo, txManager, keyRing, 15*time.Minute, "airlance-api")
	ctx := context.Background()
	userID := uuid.New()

	res, err := uc.CreateClient(ctx, userID, "My Test Client", "127.0.0.1", "test-agent", "req-1")
	if err != nil {
		t.Fatalf("unexpected create client error: %v", err)
	}
	if res.Secret == "" || res.Client == nil {
		t.Fatalf("expected secret and client object")
	}

	tokenStr, exp, err := uc.IssueToken(ctx, res.Client.ID, res.Secret)
	if err != nil {
		t.Fatalf("unexpected issue token error: %v", err)
	}
	if tokenStr == "" || exp.Before(time.Now()) {
		t.Errorf("invalid token string or expiration")
	}

	_, _, err = uc.IssueToken(ctx, res.Client.ID, "wrong-secret")
	if err == nil {
		t.Errorf("expected error with wrong client secret")
	}

	if err := uc.RevokeClient(ctx, userID, res.Client.ID, "127.0.0.1", "test-agent", "req-2"); err != nil {
		t.Fatalf("unexpected revoke error: %v", err)
	}

	_, _, err = uc.IssueToken(ctx, res.Client.ID, res.Secret)
	if err == nil {
		t.Errorf("expected error issuing token for revoked client")
	}
}
