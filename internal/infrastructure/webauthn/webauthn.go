package webauthn

import (
	"bytes"
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
	ErrNilWebAuthn = errors.New("webauthn: uninitialized engine")
)

type Engine struct {
	w *gowebauthn.WebAuthn
}

var _ passkey.WebAuthnService = (*Engine)(nil)

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

type WebAuthnUser struct {
	User        *user.User
	Credentials []*passkey.Credential
}

func (u *WebAuthnUser) WebAuthnID() []byte {
	return u.User.ID[:]
}

func (u *WebAuthnUser) WebAuthnName() string {
	return u.User.ID.String()
}

func (u *WebAuthnUser) WebAuthnDisplayName() string {
	return u.User.ID.String()
}

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

func (u *WebAuthnUser) WebAuthnIcon() string {
	return ""
}

func (e *Engine) BeginRegistration(u *user.User, existingCreds []*passkey.Credential) ([]byte, []byte, error) {
	if e == nil || e.w == nil {
		return nil, nil, ErrNilWebAuthn
	}
	wau := &WebAuthnUser{User: u, Credentials: existingCreds}
	creation, sessionData, err := e.w.BeginRegistration(
		wau,
		gowebauthn.WithResidentKeyRequirement(protocol.ResidentKeyRequirementRequired),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: begin registration failed: %w", err)
	}

	creationJSON, err := json.Marshal(creation)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: marshal creation failed: %w", err)
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: marshal session data failed: %w", err)
	}

	return creationJSON, sessionBytes, nil
}

func (e *Engine) FinishRegistration(u *user.User, existingCreds []*passkey.Credential, sessionData []byte, responsePayload []byte) (*passkey.VerifiedCredential, error) {
	if e == nil || e.w == nil {
		return nil, ErrNilWebAuthn
	}
	var sd gowebauthn.SessionData
	if err := json.Unmarshal(sessionData, &sd); err != nil {
		return nil, fmt.Errorf("webauthn: parse session data failed: %w", err)
	}

	wau := &WebAuthnUser{User: u, Credentials: existingCreds}
	dummyReq, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(responsePayload))
	if err != nil {
		return nil, fmt.Errorf("webauthn: request adapter failed: %w", err)
	}
	dummyReq.Header.Set("Content-Type", "application/json")

	cred, err := e.w.FinishRegistration(wau, sd, dummyReq)
	if err != nil {
		return nil, fmt.Errorf("webauthn: finish registration failed: %w", err)
	}

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	var aaguid *uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		id, err := uuid.FromBytes(cred.Authenticator.AAGUID)
		if err == nil {
			aaguid = &id
		}
	}

	var actualAAGUID uuid.UUID
	if aaguid != nil {
		actualAAGUID = *aaguid
	}

	return &passkey.VerifiedCredential{
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Transports:   transports,
		AAGUID:       actualAAGUID,
	}, nil
}

func (e *Engine) BeginLogin() ([]byte, []byte, error) {
	if e == nil || e.w == nil {
		return nil, nil, ErrNilWebAuthn
	}
	assertion, sessionData, err := e.w.BeginDiscoverableLogin(
		gowebauthn.WithUserVerification(protocol.VerificationRequired),
	)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: begin discoverable login failed: %w", err)
	}

	assertionJSON, err := json.Marshal(assertion)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: marshal assertion failed: %w", err)
	}

	sessionBytes, err := json.Marshal(sessionData)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: marshal session data failed: %w", err)
	}

	return assertionJSON, sessionBytes, nil
}

func (e *Engine) FinishLogin(ctx context.Context, sessionData []byte, responsePayload []byte, lookup passkey.UserLookupFunc) (*passkey.VerifiedCredential, *user.User, error) {
	if e == nil || e.w == nil {
		return nil, nil, ErrNilWebAuthn
	}
	var sd gowebauthn.SessionData
	if err := json.Unmarshal(sessionData, &sd); err != nil {
		return nil, nil, fmt.Errorf("webauthn: parse session data failed: %w", err)
	}

	var resolvedUser *user.User
	userHandler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		u, creds, err := lookup(ctx, rawID, userHandle)
		if err != nil {
			return nil, err
		}
		resolvedUser = u
		return &WebAuthnUser{User: u, Credentials: creds}, nil
	}

	dummyReq, err := http.NewRequest(http.MethodPost, "", bytes.NewReader(responsePayload))
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: request adapter failed: %w", err)
	}
	dummyReq.Header.Set("Content-Type", "application/json")

	gowebauthnUser, cred, err := e.w.FinishPasskeyLogin(userHandler, sd, dummyReq)
	if err != nil {
		return nil, nil, fmt.Errorf("webauthn: finish passkey login failed: %w", err)
	}

	if resolvedUser == nil && gowebauthnUser != nil {
		if wau, ok := gowebauthnUser.(*WebAuthnUser); ok {
			resolvedUser = wau.User
		}
	}

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	var actualAAGUID uuid.UUID
	if len(cred.Authenticator.AAGUID) == 16 {
		if id, err := uuid.FromBytes(cred.Authenticator.AAGUID); err == nil {
			actualAAGUID = id
		}
	}

	return &passkey.VerifiedCredential{
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Transports:   transports,
		AAGUID:       actualAAGUID,
	}, resolvedUser, nil
}
