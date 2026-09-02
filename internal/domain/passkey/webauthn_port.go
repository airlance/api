package passkey

import (
	"context"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/user"
)

// VerifiedCredential represents the validated passkey credential resulting from registration or login verification.
type VerifiedCredential struct {
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	AAGUID       uuid.UUID
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
