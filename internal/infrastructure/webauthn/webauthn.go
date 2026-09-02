// Package webauthn wraps go-webauthn/webauthn and provides type adaptation for passkey authentication ceremonies.
package webauthn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/user"
)

var (
	// ErrNilWebAuthn is returned when WebAuthn is not initialized.
	ErrNilWebAuthn = errors.New("webauthn: uninitialized engine")
)

// Engine wraps go-webauthn.WebAuthn.
type Engine struct {
	w *gowebauthn.WebAuthn
}

// NewEngine constructs a WebAuthn Engine from config.
func NewEngine(cfg *config.Config) (*Engine, error) {
	w, err := gowebauthn.New(&gowebauthn.Config{
		RPDisplayName: cfg.WebAuthnRPDisplayName,
		RPID:          cfg.WebAuthnRPID,
		RPOrigins:     cfg.WebAuthnRPOrigins,
	})
	if err != nil {
		return nil, fmt.Errorf("webauthn: init error: %w", err)
	}
	return &Engine{w: w}, nil
}

// WebAuthnUser adapts domain User & credentials to the go-webauthn User interface.
type WebAuthnUser struct {
	User        *user.User
	Credentials []*passkey.Credential
}

// WebAuthnID returns the user's UUID as byte slice.
func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.User.ID[:]
}

// WebAuthnName returns the user ID string.
func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.ID.String()
}

// WebAuthnDisplayName returns the user ID string.
func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.User.ID.String()
}

// WebAuthnCredentials returns the slice of registered WebAuthn credentials.
func (u *WebAuthnUser) WebAuthnCredentials() []gowebauthn.Credential {
	res := make([]gowebauthn.Credential, 0, len(u.Credentials))
	for _, c := range u.Credentials {
		var aaguidBytes []byte
		if c.AAGUID != nil {
			aaguidBytes = c.AAGUID[:]
		}
		transports := make([]protocol.AuthenticatorTransport, 0, len(c.Transports))
		for _, t := range c.Transports {
			transports = append(transports, protocol.AuthenticatorTransport(t))
		}
		res = append(res, gowebauthn.Credential{
			ID:              c.CredentialID,
			PublicKey:       c.PublicKey,
			AttestationType: "none",
			Transport:       transports,
			Flags: gowebauthn.CredentialFlags{
				UserPresent:    true,
				UserVerified:   true,
				BackupEligible: true,
				BackupState:    true,
			},
			Authenticator: gowebauthn.Authenticator{
				AAGUID:    aaguidBytes,
				SignCount: c.SignCount,
			},
		})
	}
	return res
}

// WebAuthnIcon returns an optional icon URL.
func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

// BeginRegistration starts a WebAuthn credential registration ceremony.
func (e *Engine) BeginRegistration(u *WebAuthnUser) (*protocol.CredentialCreation, *gowebauthn.SessionData, error) {
	if e == nil || e.w == nil {
		return nil, nil, ErrNilWebAuthn
	}
	creation, sessionData, err := e.w.BeginRegistration(
		u,
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: begin registration failed: %w", err)
	}
	return creation, sessionData, nil
}

// FinishRegistration validates a registration response and returns the parsed credential.
func (e *Engine) FinishRegistration(u *WebAuthnUser, sessionData gowebauthn.SessionData, r *http.Request) (*gowebauthn.Credential, error) {
	if e == nil || e.w == nil {
		return nil, ErrNilWebAuthn
	}
	cred, err := e.w.FinishRegistration(u, sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("webauthn: finish registration failed: %w", err)
	}
	return cred, nil
}

// BeginDiscoverableLogin starts a passwordless WebAuthn login ceremony without a pre-identified user.
func (e *Engine) BeginDiscoverableLogin() (*protocol.CredentialAssertion, *gowebauthn.SessionData, error) {
	if e == nil || e.w == nil {
		return nil, nil, ErrNilWebAuthn
	}
	assertion, sessionData, err := e.w.BeginDiscoverableLogin(
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: begin discoverable login failed: %w", err)
	}
	return assertion, sessionData, nil
}

// FinishDiscoverableLogin verifies a discoverable assertion response using a user finder callback.
func (e *Engine) FinishDiscoverableLogin(
	ctx context.Context,
	sessionData gowebauthn.SessionData,
	r *http.Request,
	userHandler func(rawID, userHandle []byte) (gowebauthn.User, error),
) (*gowebauthn.Credential, gowebauthn.User, error) {
	if e == nil || e.w == nil {
		return nil, nil, ErrNilWebAuthn
	}
	u, cred, err := e.w.FinishPasskeyLogin(userHandler, sessionData, r)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: finish passkey login failed: %w", err)
	}
	return cred, u, nil
}

// ParseSessionData decodes JSON session data bytes.
func ParseSessionData(data []byte) (*gowebauthn.SessionData, error) {
	var sd gowebauthn.SessionData
	if err := json.Unmarshal(data, &sd); err != nil {
		return nil, fmt.Errorf("webauthn: unmarshal session data failed: %w", err)
	}
	return &sd, nil
}

// SerializeSessionData encodes session data to JSON bytes.
func SerializeSessionData(sd *gowebauthn.SessionData) ([]byte, error) {
	return json.Marshal(sd)
}

// AAGUIDFromBytes parses a 16-byte UUID from WebAuthn AAGUID.
func AAGUIDFromBytes(b []byte) *uuid.UUID {
	if len(b) == 16 {
		id, err := uuid.FromBytes(b)
		if err == nil {
			return &id
		}
	}
	return nil
}
