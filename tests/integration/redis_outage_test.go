package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/usecase/auth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type outageLimiter struct{}

func (o *outageLimiter) Allow(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return nil, errors.New("redis: connection timeout during outage")
}

func (o *outageLimiter) Usage(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return nil, errors.New("redis: connection timeout during outage")
}

func TestRedisOutage_FailClosedProtection(t *testing.T) {
	limiter := &outageLimiter{}
	sessionSvc := sessionUC.NewUsecase(&dummySessionRepo{}, &dummyAuditRepo{}, &dummyTxManager{}, nil, 1*time.Hour)
	keyRing := crypto.KeyRing{CurrentKeyID: 1, Keys: map[uint16][]byte{1: []byte("01234567890123456789012345678901")}}

	authUC := auth.NewUsecase(
		&dummyUserRepo{},
		&dummyIdentityRepo{},
		&dummyPasskeyRepo{},
		&dummyChallengeRepo{},
		&dummyDeviceRepo{},
		&dummyAuditRepo{},
		sessionSvc,
		&dummyTxManager{},
		&dummyWebAuthnService{},
		limiter,
		nil,
		keyRing,
	)

	// 1. BeginSignup during outage -> Denied
	_, err := authUC.BeginSignup(context.Background(), "192.168.1.1")
	if err == nil {
		t.Errorf("expected fail-closed error on BeginSignup during Redis outage")
	}

	// 2. BeginLogin during outage -> Denied
	_, err = authUC.BeginLogin(context.Background(), "192.168.1.1")
	if err == nil {
		t.Errorf("expected fail-closed error on BeginLogin during Redis outage")
	}
}
