package middleware

import (
	"context"
	"crypto/ed25519"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/infrastructure/crypto"
	"airlance.org/api/internal/usecase/apiauth"
)

func TestJWTMiddleware_Validation(t *testing.T) {
	seed := []byte("01234567890123456789012345678901")
	priv := ed25519.NewKeyFromSeed(seed)
	pub := priv.Public().(ed25519.PublicKey)

	keyRing := config.Ed25519KeyRing{
		CurrentKID:  "key-1",
		PrivateKeys: map[string]ed25519.PrivateKey{"key-1": priv},
		PublicKeys:  map[string]ed25519.PublicKey{"key-1": pub},
	}

	cfg := &config.Config{
		ServiceName: "airlance-api",
		APITokenTTL: 15 * time.Minute,
		JWTKeyRing:  keyRing,
	}

	clientRepo := &mockClientRepoForJWT{
		client: &apiclient.APIClient{
			ID:         uuid.New(),
			UserID:     uuid.New(),
			TierID:     uuid.New(),
			SecretHash: crypto.HashToken("raw-secret"),
		},
	}
	tierRepo := &mockTierRepoForJWT{
		tier: &apiclient.RateLimitTier{
			ID:                clientRepo.client.TierID,
			Name:              "default",
			RequestsPerMinute: 60,
			RequestsPerDay:    5000,
		},
	}

	uc := apiauth.NewUsecase(clientRepo, tierRepo, &mockAuditRepoForJWT{}, &mockTxManagerForJWT{}, cfg)

	tokenStr, _, err := uc.IssueToken(context.Background(), clientRepo.client.ID, "raw-secret")
	if err != nil {
		t.Fatalf("failed to issue token: %v", err)
	}

	mw := JWTMiddleware(keyRing)

	var capturedCID uuid.UUID
	handler := mw(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		capturedCID = GetAPIClientID(r.Context())
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/api/v1/getMe", nil)
	req.Header.Set("Authorization", "Bearer "+tokenStr)
	rec := httptest.NewRecorder()

	handler.ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Errorf("expected 200, got %d", rec.Code)
	}
	if capturedCID != clientRepo.client.ID {
		t.Errorf("expected client ID %v, got %v", clientRepo.client.ID, capturedCID)
	}
}

type mockClientRepoForJWT struct {
	client *apiclient.APIClient
}

func (m *mockClientRepoForJWT) Create(ctx context.Context, c *apiclient.APIClient) error { return nil }
func (m *mockClientRepoForJWT) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.APIClient, error) {
	return m.client, nil
}
func (m *mockClientRepoForJWT) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*apiclient.APIClient, error) {
	return nil, nil
}
func (m *mockClientRepoForJWT) Revoke(ctx context.Context, id uuid.UUID) error { return nil }

type mockTierRepoForJWT struct {
	tier *apiclient.RateLimitTier
}

func (m *mockTierRepoForJWT) GetByID(ctx context.Context, id uuid.UUID) (*apiclient.RateLimitTier, error) {
	return m.tier, nil
}
func (m *mockTierRepoForJWT) GetByName(ctx context.Context, name string) (*apiclient.RateLimitTier, error) {
	return m.tier, nil
}

type mockAuditRepoForJWT struct{}

func (m *mockAuditRepoForJWT) Record(ctx context.Context, e *audit.Event) error { return nil }

type mockTxManagerForJWT struct{}

func (m *mockTxManagerForJWT) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}
