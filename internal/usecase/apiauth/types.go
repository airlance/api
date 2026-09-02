package apiauth

import (
	"crypto/ed25519"
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"airlance.org/api/internal/domain/apiclient"
)

var (
	ErrInvalidClientCredentials = errors.New("apiauth: invalid client credentials")
	ErrForbidden                = errors.New("apiauth: forbidden client operation")
)

type APIClaims struct {
	jwt.RegisteredClaims
	ClientID          string `json:"client_id"`
	RequestsPerMinute int    `json:"rpm"`
	RequestsPerDay    int    `json:"rpd"`
}

type KeyRing struct {
	CurrentKID  string
	PrivateKeys map[string]ed25519.PrivateKey
}

type ClientCreationResult struct {
	Client       *apiclient.APIClient `json:"client"`
	Secret       string               `json:"secret"`
	TierName     string               `json:"tier_name"`
	RPMAllowance int                  `json:"requests_per_minute"`
	RPDAllowance int                  `json:"requests_per_day"`
}
