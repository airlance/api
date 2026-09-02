package passkey

import (
	"context"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/user"
)

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

// UserLookupFunc resolves a user and their registered credentials from the credential ID or user handle.
type UserLookupFunc func(ctx context.Context, rawCredentialID, userHandle []byte) (*user.User, []*Credential, error)

// WebAuthnService defines the usecase-facing port for WebAuthn/Passkey ceremonies.
// Transport layers pass clean JSON payloads without leaking HTTP or third-party types into usecases.
type WebAuthnService interface {
	BeginRegistration(u *user.User, existingCreds []*Credential) (creationJSON []byte, sessionData []byte, err error)
	FinishRegistration(u *user.User, existingCreds []*Credential, sessionData []byte, responsePayload []byte) (*VerifiedCredential, error)
	BeginLogin() (assertionJSON []byte, sessionData []byte, err error)
	FinishLogin(ctx context.Context, sessionData []byte, responsePayload []byte, lookup UserLookupFunc) (*VerifiedCredential, *user.User, error)
}
