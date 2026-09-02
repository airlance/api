package auth

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/user"
)

// BeginLogin initiates discoverable passkey login.
func (u *Usecase) BeginLogin(ctx context.Context, ip string) (*LoginOptionsResult, error) {
	if ip != "" {
		if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:login_opts:ip:%s", ip)); err != nil {
			return nil, err
		}
	}

	assertionJSON, sdBytes, err := u.webAuthnService.BeginLogin()
	if err != nil {
		return nil, fmt.Errorf("auth: begin login error: %w", err)
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
		Assertion:   json.RawMessage(assertionJSON),
	}, nil
}

// FinishLogin validates discoverable passkey assertion and issues a session.
func (u *Usecase) FinishLogin(
	ctx context.Context,
	challengeID uuid.UUID,
	responsePayload []byte,
	rawDeviceID string,
	platform string,
	appVersion *string,
	ip, userAgent, requestID string,
) (*AuthSuccessResult, error) {
	if ip != "" {
		if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:login_verify:ip:%s", ip)); err != nil {
			return nil, err
		}
	}

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

	var resolvedCred *passkey.Credential
	var resolvedIdent *identity.Identity

	lookupFunc := func(lookupCtx context.Context, rawCredentialID, userHandle []byte) (*user.User, []*passkey.Credential, error) {
		credRecord, err := u.passkeyRepo.GetByCredentialID(lookupCtx, rawCredentialID)
		if err != nil {
			return nil, nil, err
		}
		resolvedCred = credRecord

		ident, err := u.identityRepo.GetByID(lookupCtx, credRecord.IdentityID)
		if err != nil {
			return nil, nil, err
		}
		resolvedIdent = ident

		uRecord, err := u.userRepo.GetByID(lookupCtx, ident.UserID)
		if err != nil {
			return nil, nil, err
		}

		allCreds, err := u.passkeyRepo.ListByIdentityID(lookupCtx, ident.ID)
		if err != nil {
			return nil, nil, err
		}

		return uRecord, allCreds, nil
	}

	// 2. Perform WebAuthn verification
	cred, resolvedUser, err := u.webAuthnService.FinishLogin(ctx, ch.SessionData, responsePayload, lookupFunc)
	if err != nil {
		_ = u.recordAuthFailure(ctx, nil, "login", ip, userAgent, requestID, err.Error())
		return nil, fmt.Errorf("auth: passkey login failed: %w", err)
	}

	if resolvedUser == nil || resolvedCred == nil || resolvedIdent == nil {
		return nil, errors.New("auth: failed to resolve user from credential")
	}

	// 3. Update credential sign count and touch device
	now := time.Now()
	_ = u.passkeyRepo.UpdateSignCount(ctx, resolvedCred.ID, cred.SignCount, now)

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
