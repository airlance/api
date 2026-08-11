package authidentity

import (
	"errors"
	"time"

	"github.com/airlance/api/internal/domain/account"
)

type Provider string

const (
	ProviderEmail  Provider = "email"
	ProviderGithub Provider = "github"
)

type AuthIdentityID uint64

type AuthIdentity struct {
	ID             AuthIdentityID
	AccountID      account.AccountID
	Provider       Provider
	ProviderUserID string
	ProviderEmail  string
	Metadata       map[string]any
	CreatedAt      time.Time
	UpdatedAt      time.Time
}

var (
	ErrIdentityNotFound      = errors.New("auth identity not found")
	ErrIdentityAlreadyLinked = errors.New("identity already linked to another account")
)
