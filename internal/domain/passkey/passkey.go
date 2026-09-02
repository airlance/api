// Package passkey defines WebAuthn credentials, challenges, and repository contracts.
package passkey

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrCredentialNotFound is returned when a passkey credential cannot be found.
	ErrCredentialNotFound = errors.New("passkey: credential not found")
	// ErrChallengeNotFound is returned when a challenge does not exist or was already consumed.
	ErrChallengeNotFound = errors.New("passkey: challenge not found or already consumed")
	// ErrChallengeExpired is returned when a challenge is consumed after its expiration.
	ErrChallengeExpired = errors.New("passkey: challenge expired")
	// ErrVerificationFailed is returned when WebAuthn verification fails.
	ErrVerificationFailed = errors.New("passkey: verification failed")
)

// ChallengeType denotes the intended purpose of the WebAuthn ceremony.
type ChallengeType string

const (
	ChallengeTypeSignup         ChallengeType = "signup"
	ChallengeTypeRegistration   ChallengeType = "registration"
	ChallengeTypeAuthentication ChallengeType = "authentication"
)

// Credential represents a registered WebAuthn credential on a user's authenticator.
type Credential struct {
	ID           uuid.UUID
	IdentityID   uuid.UUID
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	AAGUID       *uuid.UUID
	CreatedAt    time.Time
	LastUsedAt   *time.Time
}

// Challenge represents an ephemeral ceremony challenge state.
type Challenge struct {
	ID          uuid.UUID
	UserID      *uuid.UUID
	Type        ChallengeType
	SessionData []byte
	ExpiresAt   time.Time
}

// CredentialRepo defines persistence operations for WebAuthn credentials.
type CredentialRepo interface {
	Create(ctx context.Context, cred *Credential) error
	GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Credential, error)
	ListByIdentityID(ctx context.Context, identityID uuid.UUID) ([]*Credential, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Credential, error)
	UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsedAt time.Time) error
	DeleteByID(ctx context.Context, id uuid.UUID) error
}

// ChallengeRepo defines persistence operations for ephemeral WebAuthn challenges.
type ChallengeRepo interface {
	Create(ctx context.Context, ch *Challenge) error
	// ConsumeByID atomically deletes and returns the challenge in a single query to prevent replay races.
	ConsumeByID(ctx context.Context, id uuid.UUID) (*Challenge, error)
	CleanupExpired(ctx context.Context, before time.Time) (int64, error)
}
