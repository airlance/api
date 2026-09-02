package passkey

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrCredentialNotFound = errors.New("passkey: credential not found")
	ErrChallengeNotFound  = errors.New("passkey: challenge not found or already consumed")
	ErrChallengeExpired   = errors.New("passkey: challenge expired")
	ErrVerificationFailed = errors.New("passkey: verification failed")
)

type ChallengeType string

const (
	ChallengeTypeSignup         ChallengeType = "signup"
	ChallengeTypeRegistration   ChallengeType = "registration"
	ChallengeTypeAuthentication ChallengeType = "authentication"
)

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

type Challenge struct {
	ID          uuid.UUID
	UserID      *uuid.UUID
	Type        ChallengeType
	SessionData []byte
	ExpiresAt   time.Time
}

type VerifiedCredential struct {
	CredentialID []byte
	PublicKey    []byte
	SignCount    uint32
	Transports   []string
	AAGUID       uuid.UUID
}
