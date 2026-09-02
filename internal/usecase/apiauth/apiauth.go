// Package apiauth implements API client registration, secret management, and short-lived Ed25519 JWT minting.
package apiauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/infrastructure/crypto"
	"airlance.org/api/internal/infrastructure/database"
)

var (
	// ErrInvalidClientCredentials is returned when an invalid client secret or ID is presented.
	ErrInvalidClientCredentials = errors.New("apiauth: invalid client credentials")
	// ErrForbidden is returned when a caller attempts an operation on a client they do not own.
	ErrForbidden = errors.New("apiauth: forbidden client operation")
)

// APIClaims represents JWT claims minted for external API clients.
type APIClaims struct {
	jwt.RegisteredClaims
	ClientID          string `json:"client_id"`
	RequestsPerMinute int    `json:"rpm"`
	RequestsPerDay    int    `json:"rpd"`
}

// Usecase provides API client management and token issuance.
type Usecase struct {
	clientRepo apiclient.Repository
	tierRepo   apiclient.TierRepository
	auditRepo  audit.Repository
	txManager  database.TxManager
	cfg        *config.Config
}

// NewUsecase constructs an API Auth Usecase.
func NewUsecase(
	clientRepo apiclient.Repository,
	tierRepo apiclient.TierRepository,
	auditRepo audit.Repository,
	txManager database.TxManager,
	cfg *config.Config,
) *Usecase {
	return &Usecase{
		clientRepo: clientRepo,
		tierRepo:   tierRepo,
		auditRepo:  auditRepo,
		txManager:  txManager,
		cfg:        cfg,
	}
}

// ClientCreationResult contains client details and the one-time plaintext secret.
type ClientCreationResult struct {
	Client       *apiclient.APIClient `json:"client"`
	Secret       string               `json:"secret"`
	TierName     string               `json:"tier_name"`
	RPMAllowance int                  `json:"requests_per_minute"`
	RPDAllowance int                  `json:"requests_per_day"`
}

// CreateClient creates a new API client with the default tier and returns the plaintext secret once.
func (u *Usecase) CreateClient(ctx context.Context, userID uuid.UUID, name, ip, userAgent, requestID string) (*ClientCreationResult, error) {
	defaultTier, err := u.tierRepo.GetByName(ctx, "default")
	if err != nil {
		return nil, fmt.Errorf("apiauth: get default tier failed: %w", err)
	}

	secretPlaintext, secretHash, err := crypto.GenerateOpaqueToken(32)
	if err != nil {
		return nil, fmt.Errorf("apiauth: generate secret failed: %w", err)
	}

	now := time.Now()
	newClient := &apiclient.APIClient{
		ID:         uuid.New(),
		UserID:     userID,
		TierID:     defaultTier.ID,
		Name:       name,
		SecretHash: secretHash,
		CreatedAt:  now,
		RevokedAt:  nil,
	}

	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.clientRepo.Create(txCtx, newClient); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventClientCreated,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"client_id": newClient.ID.String(),
				"name":      name,
				"tier":      defaultTier.Name,
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return nil, fmt.Errorf("apiauth: create client tx failed: %w", err)
	}

	return &ClientCreationResult{
		Client:       newClient,
		Secret:       secretPlaintext,
		TierName:     defaultTier.Name,
		RPMAllowance: defaultTier.RequestsPerMinute,
		RPDAllowance: defaultTier.RequestsPerDay,
	}, nil
}

// IssueToken verifies client credentials and mints a short-lived Ed25519 JWT.
func (u *Usecase) IssueToken(ctx context.Context, clientID uuid.UUID, secretPlaintext string) (string, time.Time, error) {
	client, err := u.clientRepo.GetByID(ctx, clientID)
	if err != nil {
		return "", time.Time{}, ErrInvalidClientCredentials
	}

	if client.IsRevoked() {
		return "", time.Time{}, apiclient.ErrClientRevoked
	}

	expectedHash := crypto.HashToken(secretPlaintext)
	if !crypto.ConstantTimeCompareBytes(client.SecretHash, expectedHash) {
		return "", time.Time{}, ErrInvalidClientCredentials
	}

	tier, err := u.tierRepo.GetByID(ctx, client.TierID)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("apiauth: resolve tier failed: %w", err)
	}

	now := time.Now()
	expiresAt := now.Add(u.cfg.APITokenTTL)

	currentKID := u.cfg.JWTKeyRing.CurrentKID
	privKey, ok := u.cfg.JWTKeyRing.PrivateKeys[currentKID]
	if !ok {
		return "", time.Time{}, errors.New("apiauth: current signing key not found")
	}

	claims := APIClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    u.cfg.ServiceName,
			Subject:   client.UserID.String(),
			Audience:  jwt.ClaimStrings{"api"},
			ID:        uuid.New().String(),
			IssuedAt:  jwt.NewNumericDate(now),
			ExpiresAt: jwt.NewNumericDate(expiresAt),
		},
		ClientID:          client.ID.String(),
		RequestsPerMinute: tier.RequestsPerMinute,
		RequestsPerDay:    tier.RequestsPerDay,
	}

	token := jwt.NewWithClaims(jwt.SigningMethodEdDSA, claims)
	token.Header["kid"] = currentKID

	tokenString, err := token.SignedString(privKey)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("apiauth: sign JWT error: %w", err)
	}

	return tokenString, expiresAt, nil
}

// RevokeClient marks a client registration revoked.
func (u *Usecase) RevokeClient(ctx context.Context, userID, clientID uuid.UUID, ip, userAgent, requestID string) error {
	client, err := u.clientRepo.GetByID(ctx, clientID)
	if err != nil {
		return err
	}
	if client.UserID != userID {
		return ErrForbidden
	}

	now := time.Now()
	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.clientRepo.Revoke(txCtx, clientID); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventClientRevoked,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"client_id": clientID.String(),
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	return err
}

// ListClients returns all API clients owned by a user.
func (u *Usecase) ListClients(ctx context.Context, userID uuid.UUID) ([]*apiclient.APIClient, error) {
	return u.clientRepo.ListByUserID(ctx, userID)
}
