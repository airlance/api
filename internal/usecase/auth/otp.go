package auth

import (
	"context"
	"errors"
	"fmt"
	"net/mail"
	"strings"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/mailer"
	"airlance.org/api/internal/domain/otp"
	"airlance.org/api/internal/domain/ratelimit"
)

type OTPRequestResult struct {
	RequestID uuid.UUID
	ExpiresAt time.Time
}

func normalizeEmail(email string) (string, error) {
	email = strings.TrimSpace(strings.ToLower(email))
	addr, err := mail.ParseAddress(email)
	if err != nil || addr.Address != email {
		return "", errors.New("invalid email address")
	}
	return email, nil
}

func (u *Usecase) checkOTPLimits(ctx context.Context, key string, limits []ratelimit.Limit) error {
	if u.limiter == nil {
		return nil
	}
	results, err := u.limiter.Allow(ctx, key, limits)
	if err != nil {
		return fmt.Errorf("%w: limiter check failed: %v", ratelimit.ErrRateLimitExceeded, err)
	}
	for _, res := range results {
		if !res.Allowed {
			return ratelimit.ErrRateLimitExceeded
		}
	}
	return nil
}

func (u *Usecase) RequestLinkEmail(ctx context.Context, userID uuid.UUID, rawEmail, ip string) (*OTPRequestResult, error) {
	email, err := normalizeEmail(rawEmail)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", otp.ErrInvalidCode, err)
	}

	if err := u.checkOTPLimits(ctx, fmt.Sprintf("otp:link:user:%s", userID.String()), []ratelimit.Limit{
		{Name: "otp_link_user_hour", Max: 3, Window: time.Hour},
	}); err != nil {
		return nil, err
	}

	if ip != "" {
		if err := u.checkOTPLimits(ctx, fmt.Sprintf("otp:link:ip:%s", ip), []ratelimit.Limit{
			{Name: "otp_link_ip_hour", Max: 10, Window: time.Hour},
		}); err != nil {
			return nil, err
		}
	}

	if existing, err := u.identityRepo.GetByKindAndIdentifier(ctx, identity.KindEmailOTP, email); err == nil {
		if existing.Verified && existing.UserID != userID {
			return nil, otp.ErrAlreadyLinked
		}
	}

	if err := u.otpRepo.InvalidateActive(ctx, email, otp.PurposeLinkEmail); err != nil {
		return nil, err
	}

	code, hash, keyID, err := crypto.GenerateNumericCode(u.otpCodeLength, u.otpHMACKeyRing)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	rec := &otp.Code{
		ID:          uuid.New(),
		UserID:      userID,
		Email:       email,
		Purpose:     otp.PurposeLinkEmail,
		CodeHash:    hash,
		KeyID:       keyID,
		Attempts:    0,
		MaxAttempts: u.otpMaxAttempts,
		ExpiresAt:   now.Add(u.otpTTL),
		CreatedAt:   now,
	}
	if err := u.otpRepo.Create(ctx, rec); err != nil {
		return nil, err
	}

	if u.mailer != nil {
		_ = u.mailer.Send(ctx, mailer.Message{
			To:      email,
			Subject: "Your verification code",
			Text:    fmt.Sprintf("Your code is %s. It expires in %d minutes.", code, int(u.otpTTL.Minutes())),
		})
	}

	_ = u.auditRepo.Record(ctx, &audit.Event{
		ID:         uuid.New(),
		OccurredAt: now,
		UserID:     &userID,
		ActorType:  "user",
		ActorID:    &userID,
		EventType:  audit.EventAuthOTPRequested,
		IP:         ip,
		CreatedAt:  now,
		Metadata:   map[string]any{"purpose": string(otp.PurposeLinkEmail)},
	})

	return &OTPRequestResult{RequestID: rec.ID, ExpiresAt: rec.ExpiresAt}, nil
}

func (u *Usecase) VerifyLinkEmail(ctx context.Context, userID, requestID uuid.UUID, code, ip string) (*identity.Identity, error) {
	if err := u.checkOTPLimits(ctx, fmt.Sprintf("otp:verify:request:%s", requestID.String()), []ratelimit.Limit{
		{Name: "otp_verify_req_10min", Max: 5, Window: 10 * time.Minute},
	}); err != nil {
		return nil, err
	}

	if ip != "" {
		if err := u.checkOTPLimits(ctx, fmt.Sprintf("otp:verify:ip:%s", ip), []ratelimit.Limit{
			{Name: "otp_verify_ip_hour", Max: 20, Window: time.Hour},
		}); err != nil {
			return nil, err
		}
	}

	rec, err := u.consumeOTP(ctx, userID, requestID, code)
	if err != nil {
		return nil, err
	}

	now := time.Now()
	ident := &identity.Identity{
		ID:         uuid.New(),
		UserID:     userID,
		Kind:       identity.KindEmailOTP,
		Identifier: rec.Email,
		Verified:   true,
		CreatedAt:  now,
	}

	err = u.txManager.WithTx(ctx, func(txCtx context.Context) error {
		if err := u.identityRepo.Create(txCtx, ident); err != nil {
			return err
		}
		return u.auditRepo.Record(txCtx, &audit.Event{
			ID:         uuid.New(),
			OccurredAt: now,
			UserID:     &userID,
			ActorType:  "user",
			ActorID:    &userID,
			EventType:  audit.EventAuthEmailLinked,
			IP:         ip,
			Metadata:   map[string]any{"identity_id": ident.ID.String()},
			CreatedAt:  now,
		})
	})
	if err != nil {
		return nil, fmt.Errorf("auth: link email tx failed: %w", err)
	}

	return ident, nil
}

func (u *Usecase) consumeOTP(ctx context.Context, userID, requestID uuid.UUID, code string) (*otp.Code, error) {
	rec, err := u.otpRepo.GetActiveByID(ctx, requestID)
	if err != nil {
		return nil, err
	}

	if rec.UserID != userID || rec.Purpose != otp.PurposeLinkEmail {
		return nil, otp.ErrNotFound
	}

	attempts, err := u.otpRepo.IncrementAttempts(ctx, requestID)
	if err != nil {
		return nil, err
	}
	if attempts > rec.MaxAttempts {
		return nil, otp.ErrTooManyAttempts
	}

	if !crypto.VerifyNumericCode(code, rec.CodeHash, rec.KeyID, u.otpHMACKeyRing) {
		return nil, otp.ErrInvalidCode
	}

	if err := u.otpRepo.ConsumeByID(ctx, requestID); err != nil {
		return nil, err
	}

	return rec, nil
}
