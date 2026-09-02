package apiauth

import (
	"context"
	"errors"
	"fmt"
	"time"

	"github.com/golang-jwt/jwt/v5"
	"github.com/google/uuid"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/crypto"
)

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
	expiresAt := now.Add(u.tokenTTL)

	currentKID := u.keyRing.CurrentKID
	privKey, ok := u.keyRing.PrivateKeys[currentKID]
	if !ok {
		return "", time.Time{}, errors.New("apiauth: current signing key not found")
	}

	claims := APIClaims{
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    u.serviceName,
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
