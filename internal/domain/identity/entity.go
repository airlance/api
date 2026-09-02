package identity

import (
	"errors"
	"time"

	"github.com/google/uuid"
)

var (
	ErrNotFound        = errors.New("identity: not found")
	ErrAlreadyExists   = errors.New("identity: already exists")
	ErrUnsupportedKind = errors.New("identity: unsupported kind")
)

type Kind string

const (
	KindPasskey  Kind = "passkey"
	KindEmailOTP Kind = "email_otp"
)

type Identity struct {
	ID         uuid.UUID
	UserID     uuid.UUID
	Kind       Kind
	Identifier string
	Verified   bool
	CreatedAt  time.Time
}
