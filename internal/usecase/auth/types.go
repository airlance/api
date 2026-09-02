package auth

import (
	"encoding/json"
	"errors"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/user"
)

var (
	// ErrChallengeInvalid is returned when a WebAuthn challenge cannot be consumed or is expired.
	ErrChallengeInvalid = passkey.ErrChallengeNotFound
	// ErrCredentialForbidden is returned when a user attempts to delete a credential they do not own.
	ErrCredentialForbidden = errors.New("auth: credential does not belong to caller")
	// ErrCannotDeleteLastCredential is returned when trying to delete the user's sole authentication method.
	ErrCannotDeleteLastCredential = errors.New("auth: cannot remove last registered credential")
	// ErrDeviceForbidden is returned when a user attempts to revoke a device they do not own.
	ErrDeviceForbidden = errors.New("auth: device does not belong to caller")
	// ErrRateLimitExceeded is returned when rate limits are hit or limiter is unavailable in fail-closed mode.
	ErrRateLimitExceeded = errors.New("auth: rate limit exceeded")
)

// SignupOptionsResult contains the ceremony options and challenge ID for registration.
type SignupOptionsResult struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	Creation    json.RawMessage `json:"creation"`
}

// LoginOptionsResult contains the assertion options and challenge ID for discoverable login.
type LoginOptionsResult struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
}

// AuthSuccessResult contains session tokens and user info after successful authentication.
type AuthSuccessResult struct {
	Token     string           `json:"token"`
	Session   *session.Session `json:"session"`
	User      *user.User       `json:"user"`
	DeviceID  *uuid.UUID       `json:"device_id,omitempty"`
	IsNewUser bool             `json:"is_new_user"`
}
