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
)

func (u *Usecase) BeginRegisterCredential(ctx context.Context, userID uuid.UUID, ip string) (*SignupOptionsResult, error) {
	if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:reg_opts:user:%s", userID.String())); err != nil {
		return nil, err
	}

	uRecord, err := u.userRepo.GetByID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: user not found: %w", err)
	}

	creds, err := u.passkeyRepo.ListByUserID(ctx, userID)
	if err != nil {
		return nil, fmt.Errorf("auth: list credentials error: %w", err)
	}

	creationJSON, sdBytes, err := u.webAuthnService.BeginRegistration(uRecord, creds)
	if err != nil {
		return nil, fmt.Errorf("auth: begin credential registration failed: %w", err)
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
		Creation:    json.RawMessage(creationJSON),
	}, nil
}

func (u *Usecase) FinishRegisterCredential(
	ctx context.Context,
	userID, challengeID uuid.UUID,
	responsePayload []byte,
	ip, userAgent, requestID string,
) (*passkey.Credential, error) {
	if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:reg_verify:user:%s", userID.String())); err != nil {
		return nil, err
	}

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

	cred, err := u.webAuthnService.FinishRegistration(uRecord, creds, ch.SessionData, responsePayload)
	if err != nil {
		return nil, fmt.Errorf("auth: finish registration failed: %w", err)
	}

	ident, err := u.identityRepo.GetByKindAndIdentifier(ctx, identity.KindPasskey, userID.String())
	if err != nil {
		return nil, fmt.Errorf("auth: passkey identity not found: %w", err)
	}

	now := time.Now()
	newCred := &passkey.Credential{
		ID:           uuid.New(),
		IdentityID:   ident.ID,
		CredentialID: cred.CredentialID,
		PublicKey:    cred.PublicKey,
		SignCount:    cred.SignCount,
		Transports:   cred.Transports,
		AAGUID:       &cred.AAGUID,
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

func (u *Usecase) DeleteCredential(ctx context.Context, userID, credentialID uuid.UUID, ip, userAgent, requestID string) error {
	if err := u.checkChallengeRateLimit(ctx, fmt.Sprintf("auth:del_cred:user:%s", userID.String())); err != nil {
		return err
	}

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

func (u *Usecase) ListCredentials(ctx context.Context, userID uuid.UUID) ([]*passkey.Credential, error) {
	return u.passkeyRepo.ListByUserID(ctx, userID)
}
