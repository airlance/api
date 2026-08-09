package authidentity

import (
	"errors"
	"time"
)

var ErrNotFound = errors.New("authidentity: not found")

type Provider string

const (
	ProviderEmail  Provider = "email"
	ProviderGitHub Provider = "github"
	ProviderQRCode Provider = "qrcode"
)

type Identity struct {
	ID         int64
	UserID     int32
	Provider   Provider
	Identifier string
	CreatedAt  time.Time
	LastUsedAt time.Time
}
