package apiauth

import (
	"crypto/ed25519"
	"errors"

	"github.com/golang-jwt/jwt/v5"

	"airlance.org/api/internal/domain/apiclient"
)

var (
	// ErrInvalidClientCredentials is returned when an invalid client secret or ID is presented.
	ErrInvalidClientCredentials = errors.New("apiauth: invalid client credentials")
	// ErrForbidden is returned when a caller attempts an operation on a client they do not own.
	ErrForbidden = errors.New("apiauth: forbidden client operation")
)

// APIClaims represents JWT claims minted for external API clients.
type APIClaims struct {
	jwt.RegisteredClaims
	ClientID          string `json:"client_id"`
	RequestsPerMinute int    `json:"rpm"`
	RequestsPerDay    int    `json:"rpd"`
}

// KeyRing defines the signing key ring interface for API JWTs.
type KeyRing struct {
	CurrentKID  string
	PrivateKeys map[string]ed25519.PrivateKey
}

// ClientCreationResult contains client details and the one-time plaintext secret.
type ClientCreationResult struct {
	Client       *apiclient.APIClient `json:"client"`
	Secret       string               `json:"secret"`
	TierName     string               `json:"tier_name"`
	RPMAllowance int                  `json:"requests_per_minute"`
	RPDAllowance int                  `json:"requests_per_day"`
}
