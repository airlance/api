package v1

import (
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/apiclient"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/passkey"
)

// DeviceResponse represents a safe client-facing device representation.
type DeviceResponse struct {
	ID             uuid.UUID  `json:"id"`
	Platform       string     `json:"platform"`
	CreatedAt      time.Time  `json:"created_at"`
	LastSeenAt     time.Time  `json:"last_seen_at"`
	LastAppVersion *string    `json:"last_app_version,omitempty"`
	RevokedAt      *time.Time `json:"revoked_at,omitempty"`
}

// DeviceListResponse wraps a list of devices.
type DeviceListResponse struct {
	Devices []DeviceResponse `json:"devices"`
}

// RevokeDeviceResponse is the result of revoking a device.
type RevokeDeviceResponse struct {
	Status   string `json:"status"`
	DeviceID string `json:"device_id"`
}

// ClientResponse represents a safe client-facing API client representation.
type ClientResponse struct {
	ID        uuid.UUID  `json:"id"`
	UserID    uuid.UUID  `json:"user_id"`
	TierID    uuid.UUID  `json:"tier_id"`
	Name      string     `json:"name"`
	CreatedAt time.Time  `json:"created_at"`
	RevokedAt *time.Time `json:"revoked_at,omitempty"`
}

// CreateClientResponse is returned upon creating an API client.
type CreateClientResponse struct {
	Client ClientResponse `json:"client"`
	Secret string         `json:"secret"`
}

// ClientListResponse wraps a list of API clients.
type ClientListResponse struct {
	Clients []ClientResponse `json:"clients"`
}

// RevokeClientResponse is returned when an API client is revoked.
type RevokeClientResponse struct {
	Status   string `json:"status"`
	ClientID string `json:"client_id"`
}

// TokenResponse is returned upon successful API client token issuance.
type TokenResponse struct {
	AccessToken string `json:"access_token"`
	TokenType   string `json:"token_type"`
	ExpiresAt   string `json:"expires_at"`
	ExpiresIn   int    `json:"expires_in"`
}

// WSTicketResponse is returned when a new WebSocket ticket is issued.
type WSTicketResponse struct {
	Ticket    string `json:"ticket"`
	ExpiresAt string `json:"expires_at"`
	TTLSec    int    `json:"ttl_sec"`
}

// DeleteCredentialResponse is returned upon deleting a passkey credential.
type DeleteCredentialResponse struct {
	Status       string `json:"status"`
	CredentialID string `json:"credential_id"`
}

// CredentialResponse represents a safe client-facing passkey credential.
type CredentialResponse struct {
	ID         uuid.UUID  `json:"id"`
	AAGUID     *uuid.UUID `json:"aaguid,omitempty"`
	Transports []string   `json:"transports,omitempty"`
	CreatedAt  time.Time  `json:"created_at"`
	LastUsedAt *time.Time `json:"last_used_at,omitempty"`
}

// CredentialListResponse wraps a list of passkey credentials.
type CredentialListResponse struct {
	Credentials []CredentialResponse `json:"credentials"`
}

// StatusResponse is a generic status response.
type StatusResponse struct {
	Status string `json:"status"`
}

// WebAuthUserResponse represents the minimal user information returned upon web authentication.
type WebAuthUserResponse struct {
	ID uuid.UUID `json:"id"`
}

// WebAuthSuccessResponse is the safe public DTO for web passkey signup and login verify.
// It deliberately omits raw tokens, token hashes, and internal session structures.
type WebAuthSuccessResponse struct {
	User      WebAuthUserResponse `json:"user"`
	IsNewUser bool                `json:"is_new_user,omitempty"`
}

// NativeAuthSuccessResponse is returned by dedicated native passkey verify endpoints
// to supply native clients with a bearer session token.
type NativeAuthSuccessResponse struct {
	Token     string              `json:"token"`
	User      WebAuthUserResponse `json:"user"`
	IsNewUser bool                `json:"is_new_user,omitempty"`
}

// RateLimitUsageDTO details usage for a specific rate limit window.
type RateLimitUsageDTO struct {
	Limit     int64  `json:"limit"`
	Remaining int64  `json:"remaining"`
	ResetAt   string `json:"reset_at,omitempty"`
	WindowSec int    `json:"window_sec,omitempty"`
}

// MeResponse represents the authenticated API client profile.
type MeResponse struct {
	UserID     string                       `json:"user_id"`
	ClientID   string                       `json:"client_id"`
	RateLimits map[string]RateLimitUsageDTO `json:"rate_limits"`
}

// ToDeviceResponse maps a domain Device entity to DeviceResponse.
func ToDeviceResponse(d *device.Device) DeviceResponse {
	if d == nil {
		return DeviceResponse{}
	}
	return DeviceResponse{
		ID:             d.ID,
		Platform:       d.Platform,
		CreatedAt:      d.CreatedAt,
		LastSeenAt:     d.LastSeenAt,
		LastAppVersion: d.LastAppVersion,
		RevokedAt:      d.RevokedAt,
	}
}

// ToDeviceListResponse maps a slice of domain Device entities to DeviceListResponse.
func ToDeviceListResponse(devices []*device.Device) DeviceListResponse {
	res := make([]DeviceResponse, len(devices))
	for i, d := range devices {
		res[i] = ToDeviceResponse(d)
	}
	return DeviceListResponse{Devices: res}
}

// ToClientResponse maps a domain APIClient entity to ClientResponse.
func ToClientResponse(c *apiclient.APIClient) ClientResponse {
	if c == nil {
		return ClientResponse{}
	}
	return ClientResponse{
		ID:        c.ID,
		UserID:    c.UserID,
		TierID:    c.TierID,
		Name:      c.Name,
		CreatedAt: c.CreatedAt,
		RevokedAt: c.RevokedAt,
	}
}

// ToClientListResponse maps a slice of domain APIClient entities to ClientListResponse.
func ToClientListResponse(clients []*apiclient.APIClient) ClientListResponse {
	res := make([]ClientResponse, len(clients))
	for i, c := range clients {
		res[i] = ToClientResponse(c)
	}
	return ClientListResponse{Clients: res}
}

// ToCredentialResponse maps a domain Credential entity to CredentialResponse.
func ToCredentialResponse(c *passkey.Credential) CredentialResponse {
	if c == nil {
		return CredentialResponse{}
	}
	return CredentialResponse{
		ID:         c.ID,
		AAGUID:     c.AAGUID,
		Transports: c.Transports,
		CreatedAt:  c.CreatedAt,
		LastUsedAt: c.LastUsedAt,
	}
}

// ToCredentialListResponse maps a slice of domain Credential entities to CredentialListResponse.
func ToCredentialListResponse(credentials []*passkey.Credential) CredentialListResponse {
	res := make([]CredentialResponse, len(credentials))
	for i, c := range credentials {
		res[i] = ToCredentialResponse(c)
	}
	return CredentialListResponse{Credentials: res}
}
