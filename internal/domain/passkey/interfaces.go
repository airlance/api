package passkey

import (
	"context"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/user"
)

type CredentialRepo interface {
	Create(ctx context.Context, cred *Credential) error
	GetByCredentialID(ctx context.Context, credID []byte) (*Credential, error)
	GetByID(ctx context.Context, id uuid.UUID) (*Credential, error)
	ListByIdentityID(ctx context.Context, identityID uuid.UUID) ([]*Credential, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Credential, error)
	UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsedAt time.Time) error
	DeleteByID(ctx context.Context, id uuid.UUID) error
}

type ChallengeRepo interface {
	Create(ctx context.Context, ch *Challenge) error
	ConsumeByID(ctx context.Context, id uuid.UUID) (*Challenge, error)
	CleanupExpired(ctx context.Context, before time.Time) (int64, error)
}

type UserLookupFunc func(ctx context.Context, rawCredentialID, userHandle []byte) (*user.User, []*Credential, error)

type WebAuthnService interface {
	BeginRegistration(u *user.User, existingCreds []*Credential) (creationJSON []byte, sessionData []byte, err error)
	FinishRegistration(u *user.User, existingCreds []*Credential, sessionData []byte, responsePayload []byte) (*VerifiedCredential, error)
	BeginLogin() (assertionJSON []byte, sessionData []byte, err error)
	FinishLogin(ctx context.Context, sessionData []byte, responsePayload []byte, lookup UserLookupFunc) (*VerifiedCredential, *user.User, error)
}
