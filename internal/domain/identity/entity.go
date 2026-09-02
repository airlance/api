package identity

import (
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
