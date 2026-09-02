package apiauth

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
)

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
