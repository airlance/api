// Package identity defines user identities (passkey, email OTP) and authentication provider contracts.
package identity

import (
	"context"
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	// ErrNotFound is returned when an identity is not found.
	ErrNotFound = errors.New("identity: not found")
	// ErrAlreadyExists is returned when an identity already exists.
	ErrAlreadyExists = errors.New("identity: already exists")
	// ErrUnsupportedKind is returned when an unhandled identity kind is requested.
	ErrUnsupportedKind = errors.New("identity: unsupported kind")
)

// Kind represents the identity authentication method.
type Kind string

const (
	KindPasskey  Kind = "passkey"
	KindEmailOTP Kind = "email_otp"
)

// Identity represents an authentication identity tied to a User.
type Identity struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Kind       Kind
	Identifier string
	Verified   bool
	CreatedAt  time.Time
}

// Repository defines storage operations for identities.
type Repository interface {
	Create(ctx context.Context, ident *Identity) error
	GetByID(ctx context.Context, id uuid.UUID) (*Identity, error)
	GetByKindAndIdentifier(ctx context.Context, kind Kind, identifier string) (*Identity, error)
	ListByUserID(ctx context.Context, userID uuid.UUID) ([]*Identity, error)
	MarkVerified(ctx context.Context, id uuid.UUID) error
}

// AuthProvider defines the interface implemented by specific authentication mechanisms.
type AuthProvider interface {
	Kind() Kind
}
