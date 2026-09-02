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
	ErrChallengeInvalid           = passkey.ErrChallengeNotFound
	ErrCredentialForbidden        = errors.New("auth: credential does not belong to caller")
	ErrCannotDeleteLastCredential = errors.New("auth: cannot remove last registered credential")
	ErrDeviceForbidden            = errors.New("auth: device does not belong to caller")
	ErrRateLimitExceeded          = errors.New("auth: rate limit exceeded")
)

type SignupOptionsResult struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	Creation    json.RawMessage `json:"creation"`
}

type LoginOptionsResult struct {
	ChallengeID uuid.UUID       `json:"challenge_id"`
	Assertion   json.RawMessage `json:"assertion"`
}

type AuthSuccessResult struct {
	Token     string           `json:"token"`
	Session   *session.Session `json:"session"`
	User      *user.User       `json:"user"`
	DeviceID  *uuid.UUID       `json:"device_id,omitempty"`
	IsNewUser bool             `json:"is_new_user"`
}
