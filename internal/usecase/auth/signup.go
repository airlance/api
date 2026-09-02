package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/user"
)

// BeginSignup initiates passkey registration for a new user.
func (u *Usecase) BeginSignup(ctx context.Context, ip string) (*SignupOptionsResult, error) {
	if ip != "" {
		if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:signup_opts:ip:%s", ip)); err != nil {
			return nil, err
		}
	}

	tempUserID := uuid.New()
	tempUser := &user.User{ID: tempUserID, CreatedAt: time.Now()}

	creationJSON, sdBytes, err := u.webAuthnService.BeginRegistration(tempUser, nil)
	if err != nil {
		return nil, fmt.Errorf("auth: begin signup error: %w", err)
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
		Creation:    json.RawMessage(creationJSON),
	}, nil
}

// FinishSignup validates passkey creation, provisions the user, identity, credential, and session.
func (u *Usecase) FinishSignup(
	ctx context.Context,
	challengeID uuid.UUID,
	responsePayload []byte,
	rawDeviceID string,
	platform string,
	appVersion *string,
	ip, userAgent, requestID string,
) (*AuthSuccessResult, error) {
	if ip != "" {
		if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:signup_verify:ip:%s", ip)); err != nil {
			return nil, err
		}
	}

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

	tempUser := &user.User{ID: *ch.UserID, CreatedAt: time.Now()}

	// 2. Validate WebAuthn response via service port
	cred, err := u.webAuthnService.FinishRegistration(tempUser, nil, ch.SessionData, responsePayload)
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

	newCred := &passkey.Credential{
		ID:           uuid.New(),
		IdentityID:   newIdent.ID,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.SignCount,
		Transports:   cred.Transports,
		AAGUID:       &cred.AAGUID,
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
