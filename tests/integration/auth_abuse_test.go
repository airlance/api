package integration

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/user"
	"airlance.org/api/internal/usecase/auth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type failingLimiter struct{}

func (f *failingLimiter) Allow(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return nil, errors.New("redis connection refused")
}

func (f *failingLimiter) Usage(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return nil, errors.New("redis connection refused")
}

type dummyUserRepo struct{}

func (d *dummyUserRepo) Create(ctx context.Context, u *user.User) error { return nil }
func (d *dummyUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	return nil, nil
}

type dummyIdentityRepo struct{}

func (d *dummyIdentityRepo) Create(ctx context.Context, i *identity.Identity) error { return nil }
func (d *dummyIdentityRepo) GetByID(ctx context.Context, id uuid.UUID) (*identity.Identity, error) {
	return nil, nil
}
func (d *dummyIdentityRepo) GetByKindAndIdentifier(ctx context.Context, kind identity.Kind, identifier string) (*identity.Identity, error) {
	return nil, nil
}
func (d *dummyIdentityRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*identity.Identity, error) {
	return nil, nil
}
func (d *dummyIdentityRepo) MarkVerified(ctx context.Context, id uuid.UUID) error { return nil }

type dummyPasskeyRepo struct{}

func (d *dummyPasskeyRepo) Create(ctx context.Context, c *passkey.Credential) error { return nil }
func (d *dummyPasskeyRepo) GetByID(ctx context.Context, id uuid.UUID) (*passkey.Credential, error) {
	return nil, nil
}
func (d *dummyPasskeyRepo) GetByCredentialID(ctx context.Context, rawID []byte) (*passkey.Credential, error) {
	return nil, nil
}
func (d *dummyPasskeyRepo) ListByIdentityID(ctx context.Context, identID uuid.UUID) ([]*passkey.Credential, error) {
	return nil, nil
}
func (d *dummyPasskeyRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*passkey.Credential, error) {
	return nil, nil
}
func (d *dummyPasskeyRepo) UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsed time.Time) error {
	return nil
}
func (d *dummyPasskeyRepo) DeleteByID(ctx context.Context, id uuid.UUID) error { return nil }

type dummyChallengeRepo struct{}

func (d *dummyChallengeRepo) Create(ctx context.Context, ch *passkey.Challenge) error { return nil }
func (d *dummyChallengeRepo) ConsumeByID(ctx context.Context, id uuid.UUID) (*passkey.Challenge, error) {
	return nil, nil
}
func (d *dummyChallengeRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type dummyDeviceRepo struct{}

func (d *dummyDeviceRepo) Create(ctx context.Context, dev *device.Device) error { return nil }
func (d *dummyDeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	return nil, nil
}
func (d *dummyDeviceRepo) GetByHash(ctx context.Context, hash []byte) (*device.Device, error) {
	return nil, nil
}
func (d *dummyDeviceRepo) Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error {
	return nil
}
func (d *dummyDeviceRepo) RebindUser(ctx context.Context, id uuid.UUID, userID uuid.UUID, appVersion *string, lastSeen time.Time) error {
	return nil
}
func (d *dummyDeviceRepo) UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error {
	return nil
}
func (d *dummyDeviceRepo) Revoke(ctx context.Context, id uuid.UUID) error { return nil }
func (d *dummyDeviceRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	return nil, nil
}

type dummyAuditRepo struct{}

func (d *dummyAuditRepo) Record(ctx context.Context, e *audit.Event) error { return nil }

type dummySessionRepo struct{}

func (d *dummySessionRepo) Create(ctx context.Context, s *session.Session) error { return nil }
func (d *dummySessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	return nil, nil
}
func (d *dummySessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	return nil, nil
}
func (d *dummySessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	return nil, nil
}
func (d *dummySessionRepo) Revoke(ctx context.Context, tokenHash []byte) error { return nil }
func (d *dummySessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error { return nil }
func (d *dummySessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return nil
}
func (d *dummySessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}
func (d *dummySessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type dummyTxManager struct{}

func (d *dummyTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type dummyWebAuthnService struct{}

func (d *dummyWebAuthnService) BeginRegistration(u *user.User, existingCreds []*passkey.Credential) ([]byte, []byte, error) {
	return []byte(`{}`), []byte(`{}`), nil
}
func (d *dummyWebAuthnService) FinishRegistration(u *user.User, existingCreds []*passkey.Credential, sessionData []byte, responsePayload []byte) (*passkey.VerifiedCredential, error) {
	return nil, nil
}
func (d *dummyWebAuthnService) BeginLogin() ([]byte, []byte, error) {
	return []byte(`{}`), []byte(`{}`), nil
}
func (d *dummyWebAuthnService) FinishLogin(ctx context.Context, sessionData []byte, responsePayload []byte, lookup passkey.UserLookupFunc) (*passkey.VerifiedCredential, *user.User, error) {
	return nil, nil, nil
}

func TestAuth_FailClosedOnLimiterOutage(t *testing.T) {
	limiter := &failingLimiter{}
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
		nil,
		nil,
		keyRing,
		6,
		10*time.Minute,
		5,
	)

	_, err := authUC.BeginSignup(context.Background(), "127.0.0.1")
	if err == nil {
		t.Errorf("expected fail-closed error when limiter is down, got nil")
	}

	_, err = authUC.BeginLogin(context.Background(), "127.0.0.1")
	if err == nil {
		t.Errorf("expected fail-closed error on BeginLogin when limiter is down, got nil")
	}
}
