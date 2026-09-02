package passkey

import (
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

// VerifiedCredential represents the validated passkey credential resulting from registration or login verification.
type VerifiedCredential struct {
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	AAGUID       uuid.UUID
}
