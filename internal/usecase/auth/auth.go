// Package auth orchestrates authentication ceremonies, credentials, and identity lifecycle.
package auth

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/go-webauthn/webauthn/protocol"
	gowebauthn "github.com/go-webauthn/webauthn/webauthn"
	"github.com/google/uuid"

	"airlance.org/api/internal/config"
	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/user"
	"airlance.org/api/internal/infrastructure/crypto"
	"airlance.org/api/internal/infrastructure/database"
	"airlance.org/api/internal/infrastructure/webauthn"
	sessionUC "airlance.org/api/internal/usecase/session"
)

var (
	// ErrChallengeInvalid is returned when a WebAuthn challenge cannot be consumed or is expired.
	ErrChallengeInvalid = passkey.ErrChallengeNotFound
	// ErrCredentialForbidden is returned when a user attempts to delete a credential they do not own.
	ErrCredentialForbidden = errors.New("auth: credential does not belong to caller")
	// ErrCannotDeleteLastCredential is returned when trying to delete the user's sole authentication method.
	ErrCannotDeleteLastCredential = errors.New("auth: cannot remove last registered credential")
)

// Usecase provides provider-agnostic and passkey-specific authentication use cases.
type Usecase struct {
	userRepo       user.Repository
	identityRepo   identity.Repository
	passkeyRepo    passkey.CredentialRepo
	challengeRepo  passkey.ChallengeRepo
	deviceRepo     device.Repository
	auditRepo      audit.Repository
	sessionUsecase *sessionUC.Usecase
	txManager      database.TxManager
	webAuthnEngine *webauthn.Engine
	cfg            *config.Config
}

// NewUsecase constructs an Auth Usecase.
func NewUsecase(
	userRepo user.Repository,
	identityRepo identity.Repository,
	passkeyRepo passkey.CredentialRepo,
	challengeRepo passkey.ChallengeRepo,
	deviceRepo device.Repository,
	auditRepo audit.Repository,
	sessionUsecase *sessionUC.Usecase,
	txManager database.TxManager,
	webAuthnEngine *webauthn.Engine,
	cfg *config.Config,
) *Usecase {
	return &Usecase{
		userRepo:       userRepo,
		identityRepo:   identityRepo,
		passkeyRepo:    passkeyRepo,
		challengeRepo:  challengeRepo,
		deviceRepo:     deviceRepo,
		auditRepo:      auditRepo,
		sessionUsecase: sessionUsecase,
		txManager:      txManager,
		webAuthnEngine: webAuthnEngine,
		cfg:            cfg,
	}
}

// SignupOptionsResult contains the ceremony options and challenge ID for registration.
type SignupOptionsResult struct {
	ChallengeID uuid.UUID                    `json:"challenge_id"`
	Creation    *protocol.CredentialCreation `json:"creation"`
}

// LoginOptionsResult contains the assertion options and challenge ID for discoverable login.
type LoginOptionsResult struct {
	ChallengeID uuid.UUID                     `json:"challenge_id"`
	Assertion   *protocol.CredentialAssertion `json:"assertion"`
}

// AuthSuccessResult contains session tokens and user info after successful authentication.
type AuthSuccessResult struct {
	Token     string           `json:"token"`
	Session   *session.Session `json:"session"`
	User      *user.User       `json:"user"`
	DeviceID  *uuid.UUID       `json:"device_id,omitempty"`
	IsNewUser bool             `json:"is_new_user"`
}

// BeginSignup initiates passkey registration for a new user.
func (u *Usecase) BeginSignup(ctx context.Context) (*SignupOptionsResult, error) {
	tempUserID := uuid.New()
	tempUser := &user.User{ID: tempUserID, CreatedAt: time.Now()}
	wau := &webauthn.WebAuthnUser{User: tempUser}

	creation, sessionData, err := u.webAuthnEngine.BeginRegistration(wau)
	if err != nil {
		return nil, fmt.Errorf("auth: begin signup error: %w", err)
	}

	sdBytes, err := webauthn.SerializeSessionData(sessionData)
	if err != nil {
		return nil, fmt.Errorf("auth: serialize session data error: %w", err)
	}

	challengeID := uuid.New()
	ch := &passkey.Challenge{
		ID:          challengeID,
		UserID:      &tempUserID,
		Type:        passkey.ChallengeTypeSignup,
		SessionData: sdBytes,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := u.challengeRepo.Create(ctx, ch); err != nil {
		return nil, fmt.Errorf("auth: store challenge error: %w", err)
	}

	return &SignupOptionsResult{
		ChallengeID: challengeID,
		Creation:    creation,
	}, nil
}

// FinishSignup validates passkey creation, provisions the user, identity, credential, and session.
func (u *Usecase) FinishSignup(
	ctx context.Context,
	challengeID uuid.UUID,
	r *http.Request,
	rawDeviceID string,
	platform string,
	appVersion *string,
	ip, userAgent, requestID string,
) (*AuthSuccessResult, error) {
	// 1. Atomically consume challenge
	ch, err := u.challengeRepo.ConsumeByID(ctx, challengeID)
	if err != nil {
		_ = u.recordAuthFailure(ctx, nil, "signup", ip, userAgent, requestID, "invalid_or_consumed_challenge")
		return nil, fmt.Errorf("auth: consume challenge failed: %w", err)
	}
	if ch.Type != passkey.ChallengeTypeSignup || ch.UserID == nil {
		_ = u.recordAuthFailure(ctx, nil, "signup", ip, userAgent, requestID, "invalid_challenge_type")
		return nil, errors.New("auth: invalid signup challenge")
	}

	sessionData, err := webauthn.ParseSessionData(ch.SessionData)
	if err != nil {
		return nil, fmt.Errorf("auth: parse challenge data failed: %w", err)
	}

	tempUser := &user.User{ID: *ch.UserID, CreatedAt: time.Now()}
	wau := &webauthn.WebAuthnUser{User: tempUser}

	// 2. Validate WebAuthn response
	cred, err := u.webAuthnEngine.FinishRegistration(wau, *sessionData, r)
	if err != nil {
		_ = u.recordAuthFailure(ctx, ch.UserID, "signup", ip, userAgent, requestID, err.Error())
		return nil, fmt.Errorf("auth: webauthn verification failed: %w", err)
	}

	now := time.Now()
	newUser := &user.User{ID: *ch.UserID, CreatedAt: now}
	newIdent := &identity.Identity{
		ID:         uuid.New(),
		UserID:     newUser.ID,
		Kind:       identity.KindPasskey,
		Identifier: newUser.ID.String(),
		Verified:   true,
		CreatedAt:  now,
	}

	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	newCred := &passkey.Credential{
		ID:           uuid.New(),
		IdentityID:   newIdent.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Transports:   transports,
		AAGUID:       webauthn.AAGUIDFromBytes(cred.Authenticator.AAGUID),
		CreatedAt:    now,
		LastUsedAt:   &now,
	}

	var deviceID *uuid.UUID
	if rawDeviceID != "" && platform != "" {
		devID, err := u.resolveOrCreateDevice(ctx, newUser.ID, rawDeviceID, platform, appVersion)
		if err == nil {
			deviceID = &devID
		}
	}

	// 3. Atomically persist user, identity, credential, and audit log
	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.userRepo.Create(txCtx, newUser); err != nil {
			return err
		}
		if err := u.identityRepo.Create(txCtx, newIdent); err != nil {
			return err
		}
		if err := u.passkeyRepo.Create(txCtx, newCred); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &newUser.ID,
			ActorType:  "user",
			ActorID:    &newUser.ID,
			EventType:  audit.EventAuthSignupSuccess,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"identity_id":   newIdent.ID.String(),
				"credential_id": newCred.ID.String(),
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return nil, fmt.Errorf("auth: persist signup tx failed: %w", err)
	}

	// 4. Create Session
	token, sess, err := u.sessionUsecase.CreateSession(ctx, newUser.ID, newIdent.ID, deviceID, ip, userAgent, requestID)
	if err != nil {
		return nil, fmt.Errorf("auth: create session failed: %w", err)
	}

	return &AuthSuccessResult{
		Token:     token,
		Session:   sess,
		User:      newUser,
		DeviceID:  deviceID,
		IsNewUser: true,
	}, nil
}

// BeginLogin initiates discoverable passkey login.
func (u *Usecase) BeginLogin(ctx context.Context) (*LoginOptionsResult, error) {
	assertion, sessionData, err := u.webAuthnEngine.BeginDiscoverableLogin()
	if err != nil {
		return nil, fmt.Errorf("auth: begin login error: %w", err)
	}

	sdBytes, err := webauthn.SerializeSessionData(sessionData)
	if err != nil {
		return nil, fmt.Errorf("auth: serialize session data error: %w", err)
	}

	challengeID := uuid.New()
	ch := &passkey.Challenge{
		ID:          challengeID,
		UserID:      nil, // Discoverable, resolved later
		Type:        passkey.ChallengeTypeAuthentication,
		SessionData: sdBytes,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := u.challengeRepo.Create(ctx, ch); err != nil {
		return nil, fmt.Errorf("auth: store challenge error: %w", err)
	}

	return &LoginOptionsResult{
		ChallengeID: challengeID,
		Assertion:   assertion,
	}, nil
}

// FinishLogin validates discoverable passkey assertion and issues a session.
func (u *Usecase) FinishLogin(
	ctx context.Context,
	challengeID uuid.UUID,
	r *http.Request,
	rawDeviceID string,
	platform string,
	appVersion *string,
	ip, userAgent, requestID string,
) (*AuthSuccessResult, error) {
	// 1. Consume challenge
	ch, err := u.challengeRepo.ConsumeByID(ctx, challengeID)
	if err != nil {
		_ = u.recordAuthFailure(ctx, nil, "login", ip, userAgent, requestID, "invalid_or_consumed_challenge")
		return nil, fmt.Errorf("auth: consume challenge failed: %w", err)
	}
	if ch.Type != passkey.ChallengeTypeAuthentication {
		_ = u.recordAuthFailure(ctx, nil, "login", ip, userAgent, requestID, "invalid_challenge_type")
		return nil, errors.New("auth: invalid login challenge type")
	}

	sessionData, err := webauthn.ParseSessionData(ch.SessionData)
	if err != nil {
		return nil, fmt.Errorf("auth: parse challenge data failed: %w", err)
	}

	var resolvedUser *user.User
	var resolvedCred *passkey.Credential
	var resolvedIdent *identity.Identity

	userHandler := func(rawID, userHandle []byte) (gowebauthn.User, error) {
		credRecord, err := u.passkeyRepo.GetByCredentialID(ctx, rawID)
		if err != nil {
			return nil, err
		}
		resolvedCred = credRecord

		ident, err := u.identityRepo.GetByID(ctx, credRecord.IdentityID)
		if err != nil {
			return nil, err
		}
		resolvedIdent = ident

		uRecord, err := u.userRepo.GetByID(ctx, ident.UserID)
		if err != nil {
			return nil, err
		}
		resolvedUser = uRecord

		allCreds, err := u.passkeyRepo.ListByIdentityID(ctx, ident.ID)
		if err != nil {
			return nil, err
		}

		return &webauthn.WebAuthnUser{
			User:        uRecord,
			Credentials: allCreds,
		}, nil
	}

	// 2. Perform WebAuthn verification
	cred, _, err := u.webAuthnEngine.FinishDiscoverableLogin(ctx, *sessionData, r, userHandler)
	if err != nil {
		_ = u.recordAuthFailure(ctx, nil, "login", ip, userAgent, requestID, err.Error())
		return nil, fmt.Errorf("auth: passkey login failed: %w", err)
	}

	if resolvedUser == nil || resolvedCred == nil || resolvedIdent == nil {
		return nil, errors.New("auth: failed to resolve user from credential")
	}

	// 3. Update credential sign count and touch device
	now := time.Now()
	_ = u.passkeyRepo.UpdateSignCount(ctx, resolvedCred.ID, cred.Authenticator.SignCount, now)

	var deviceID *uuid.UUID
	if rawDeviceID != "" && platform != "" {
		devID, err := u.resolveOrCreateDevice(ctx, resolvedUser.ID, rawDeviceID, platform, appVersion)
		if err == nil {
			deviceID = &devID
		}
	}

	// 4. Create Session
	token, sess, err := u.sessionUsecase.CreateSession(ctx, resolvedUser.ID, resolvedIdent.ID, deviceID, ip, userAgent, requestID)
	if err != nil {
		return nil, fmt.Errorf("auth: create session failed: %w", err)
	}

	return &AuthSuccessResult{
		Token:     token,
		Session:   sess,
		User:      resolvedUser,
		DeviceID:  deviceID,
		IsNewUser: false,
	}, nil
}

// BeginRegisterCredential starts adding a new passkey credential to an existing user account.
func (u *Usecase) BeginRegisterCredential(ctx context.Context, userID uuid.UUID) (*SignupOptionsResult, error) {
	uRecord, err := u.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: user not found: %w", err)
	}

	creds, err := u.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list credentials error: %w", err)
	}

	wau := &webauthn.WebAuthnUser{User: uRecord, Credentials: creds}
	creation, sessionData, err := u.webAuthnEngine.BeginRegistration(wau)
	if err != nil {
		return nil, fmt.Errorf("auth: begin credential registration failed: %w", err)
	}

	sdBytes, err := webauthn.SerializeSessionData(sessionData)
	if err != nil {
		return nil, fmt.Errorf("auth: serialize session data error: %w", err)
	}

	challengeID := uuid.New()
	ch := &passkey.Challenge{
		ID:          challengeID,
		UserID:      &userID,
		Type:        passkey.ChallengeTypeRegistration,
		SessionData: sdBytes,
		ExpiresAt:   time.Now().Add(5 * time.Minute),
	}

	if err := u.challengeRepo.Create(ctx, ch); err != nil {
		return nil, fmt.Errorf("auth: store challenge error: %w", err)
	}

	return &SignupOptionsResult{
		ChallengeID: challengeID,
		Creation:    creation,
	}, nil
}

// FinishRegisterCredential verifies and attaches a new passkey credential to the user.
func (u *Usecase) FinishRegisterCredential(
	ctx context.Context,
	userID, challengeID uuid.UUID,
	r *http.Request,
	ip, userAgent, requestID string,
) (*passkey.Credential, error) {
	ch, err := u.challengeRepo.ConsumeByID(ctx, challengeID)
	if err != nil {
		return nil, fmt.Errorf("auth: consume challenge failed: %w", err)
	}
	if ch.Type != passkey.ChallengeTypeRegistration || ch.UserID == nil || *ch.UserID != userID {
		return nil, errors.New("auth: invalid registration challenge")
	}

	uRecord, err := u.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: user not found: %w", err)
	}

	creds, err := u.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list credentials error: %w", err)
	}

	sessionData, err := webauthn.ParseSessionData(ch.SessionData)
	if err != nil {
		return nil, fmt.Errorf("auth: parse challenge data failed: %w", err)
	}

	wau := &webauthn.WebAuthnUser{User: uRecord, Credentials: creds}
	cred, err := u.webAuthnEngine.FinishRegistration(wau, *sessionData, r)
	if err != nil {
		return nil, fmt.Errorf("auth: finish registration failed: %w", err)
	}

	ident, err := u.identityRepo.GetByKindAndIdentifier(ctx, identity.KindPasskey, userID.String())
	if err != nil {
		return nil, fmt.Errorf("auth: passkey identity not found: %w", err)
	}

	now := time.Now()
	transports := make([]string, 0, len(cred.Transport))
	for _, t := range cred.Transport {
		transports = append(transports, string(t))
	}

	newCred := &passkey.Credential{
		ID:           uuid.New(),
		IdentityID:   ident.ID,
		CredentialID: cred.ID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.Authenticator.SignCount,
		Transports:   transports,
		AAGUID:       webauthn.AAGUIDFromBytes(cred.Authenticator.AAGUID),
		CreatedAt:    now,
		LastUsedAt:   &now,
	}

	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.passkeyRepo.Create(txCtx, newCred); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventPasskeyAdded,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"credential_id": newCred.ID.String(),
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	if err != nil {
		return nil, fmt.Errorf("auth: add passkey tx failed: %w", err)
	}

	return newCred, nil
}

// DeleteCredential removes a passkey credential, verifying ownership and ensuring at least one credential remains.
func (u *Usecase) DeleteCredential(ctx context.Context, userID, credentialID uuid.UUID, ip, userAgent, requestID string) error {
	cred, err := u.passkeyRepo.GetByID(ctx, credentialID)
	if err != nil {
		return err
	}

	ident, err := u.identityRepo.GetByID(ctx, cred.IdentityID)
	if err != nil {
		return err
	}
	if ident.UserID != userID {
		return ErrCredentialForbidden
	}

	allCreds, err := u.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return err
	}
	if len(allCreds) <= 1 {
		return ErrCannotDeleteLastCredential
	}

	now := time.Now()
	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.passkeyRepo.DeleteByID(txCtx, credentialID); err != nil {
			return err
		}

		auditEv := &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventPasskeyRemoved,
			IP:         ip,
			UserAgent:  userAgent,
			RequestID:  requestID,
			Metadata: map[string]any{
				"credential_id": credentialID.String(),
			},
			CreatedAt: now,
		}
		return u.auditRepo.Record(txCtx, auditEv)
	})

	return err
}

func (u *Usecase) resolveOrCreateDevice(ctx context.Context, userID uuid.UUID, rawDeviceID, platform string, appVersion *string) (uuid.UUID, error) {
	data := []byte(rawDeviceID)
	ring := u.cfg.DeviceHMACKeyRing

	// Look up device under current and previous HMAC keys
	var matchedDevice *device.Device
	var needsRotation bool

	for _, key := range ring.Keys {
		h := crypto.ComputeHMAC(data, key)
		dev, err := u.deviceRepo.GetByHash(ctx, h)
		if err == nil && dev != nil && dev.UserID == userID && dev.IsValid() {
			matchedDevice = dev
			if !crypto.ConstantTimeCompareBytes(h, crypto.ComputeHMAC(data, ring.Keys[ring.CurrentKeyID])) {
				needsRotation = true
			}
			break
		}
	}

	now := time.Now()
	if matchedDevice != nil {
		_ = u.deviceRepo.Touch(ctx, matchedDevice.ID, appVersion, now)
		if needsRotation {
			newHash, _, _ := crypto.ComputeKeyRingHMAC(data, ring)
			_ = u.deviceRepo.UpdateHash(ctx, matchedDevice.ID, newHash)
		}
		return matchedDevice.ID, nil
	}

	// Create new device record
	currentHash, _, err := crypto.ComputeKeyRingHMAC(data, ring)
	if err != nil {
		return uuid.Nil, err
	}

	newDev := &device.Device{
		ID:                   uuid.New(),
		UserID:               userID,
		DeviceIdentifierHash: currentHash,
		Platform:             platform,
		CreatedAt:            now,
		LastSeenAt:           now,
		LastAppVersion:       appVersion,
		RevokedAt:            nil,
	}

	if err := u.deviceRepo.Create(ctx, newDev); err != nil {
		return uuid.Nil, err
	}

	return newDev.ID, nil
}

func (u *Usecase) recordAuthFailure(ctx context.Context, userID *uuid.UUID, ceremony, ip, userAgent, reqID, reason string) error {
	now := time.Now()
	ev := &audit.Event{
		ID:         uuid.New(),
		OccurredAt: now,
		UserID:     userID,
		ActorType:  "anonymous",
		ActorID:    userID,
		EventType:  audit.EventAuthLoginFailed,
		IP:         ip,
		UserAgent:  userAgent,
		RequestID:  reqID,
		Metadata: map[string]any{
			"ceremony": ceremony,
			"reason":   reason,
		},
		CreatedAt: now,
	}
	if ceremony == "signup" {
		ev.EventType = audit.EventAuthSignupFailed
	}
	return u.auditRepo.Record(ctx, ev)
}
