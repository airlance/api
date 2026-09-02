package ws

import (
	"context"
	"testing"
	"time"

	"github.com/google/uuid"

	"airlance.org/api/internal/domain/audit"
	"airlance.org/api/internal/domain/crypto"
	"airlance.org/api/internal/domain/device"
	"airlance.org/api/internal/domain/identity"
	"airlance.org/api/internal/domain/mailer"
	"airlance.org/api/internal/domain/otp"
	"airlance.org/api/internal/domain/passkey"
	"airlance.org/api/internal/domain/ratelimit"
	"airlance.org/api/internal/domain/session"
	"airlance.org/api/internal/domain/user"
	"airlance.org/api/internal/usecase/auth"
	sessionUC "airlance.org/api/internal/usecase/session"
)

type mockTxManager struct{}

func (m *mockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type mockAuditRepo struct {
	events []*audit.Event
}

func (m *mockAuditRepo) Record(ctx context.Context, ev *audit.Event) error {
	m.events = append(m.events, ev)
	return nil
}

type mockSessionRepo struct {
	sessions map[uuid.UUID]*session.Session
}

func newMockSessionRepo() *mockSessionRepo {
	return &mockSessionRepo{sessions: make(map[uuid.UUID]*session.Session)}
}

func (m *mockSessionRepo) Create(ctx context.Context, s *session.Session) error {
	m.sessions[s.ID] = s
	return nil
}

func (m *mockSessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	for _, s := range m.sessions {
		if s.RevokedAt == nil && time.Now().Before(s.ExpiresAt) {
			return s, nil
		}
	}
	return nil, session.ErrNotFound
}

func (m *mockSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	s, ok := m.sessions[id]
	if !ok {
		return nil, session.ErrNotFound
	}
	return s, nil
}

func (m *mockSessionRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*session.Session, error) {
	var list []*session.Session
	now := time.Now()
	for _, s := range m.sessions {
		if s.UserID == userID && s.RevokedAt == nil && s.ExpiresAt.After(now) {
			list = append(list, s)
		}
	}
	return list, nil
}

func (m *mockSessionRepo) Revoke(ctx context.Context, tokenHash []byte) error {
	return nil
}

func (m *mockSessionRepo) RevokeByID(ctx context.Context, id uuid.UUID) error {
	s, ok := m.sessions[id]
	if !ok {
		return session.ErrNotFound
	}
	now := time.Now()
	s.RevokedAt = &now
	return nil
}

func (m *mockSessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	now := time.Now()
	for _, s := range m.sessions {
		if s.UserID == userID {
			s.RevokedAt = &now
		}
	}
	return nil
}

func (m *mockSessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}

func (m *mockSessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockOTPRepo struct {
	codes map[uuid.UUID]*otp.Code
}

func newMockOTPRepo() *mockOTPRepo {
	return &mockOTPRepo{codes: make(map[uuid.UUID]*otp.Code)}
}

func (m *mockOTPRepo) Create(ctx context.Context, c *otp.Code) error {
	m.codes[c.ID] = c
	return nil
}

func (m *mockOTPRepo) GetActiveByID(ctx context.Context, id uuid.UUID) (*otp.Code, error) {
	c, ok := m.codes[id]
	if !ok {
		return nil, otp.ErrNotFound
	}
	now := time.Now()
	if c.ConsumedAt != nil {
		return nil, otp.ErrNotFound
	}
	if !now.Before(c.ExpiresAt) {
		return nil, otp.ErrExpired
	}
	if c.Attempts >= c.MaxAttempts {
		return nil, otp.ErrTooManyAttempts
	}
	return c, nil
}

func (m *mockOTPRepo) IncrementAttempts(ctx context.Context, id uuid.UUID) (int, error) {
	c, ok := m.codes[id]
	if !ok {
		return 0, otp.ErrNotFound
	}
	c.Attempts++
	return c.Attempts, nil
}

func (m *mockOTPRepo) ConsumeByID(ctx context.Context, id uuid.UUID) error {
	c, ok := m.codes[id]
	if !ok {
		return otp.ErrNotFound
	}
	now := time.Now()
	c.ConsumedAt = &now
	return nil
}

func (m *mockOTPRepo) InvalidateActive(ctx context.Context, email string, purpose otp.Purpose) error {
	now := time.Now()
	for _, c := range m.codes {
		if c.Email == email && c.Purpose == purpose && c.ConsumedAt == nil {
			c.ConsumedAt = &now
		}
	}
	return nil
}

func (m *mockOTPRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockMailer struct {
	sent []mailer.Message
}

func (m *mockMailer) Send(ctx context.Context, msg mailer.Message) error {
	m.sent = append(m.sent, msg)
	return nil
}

type mockIdentityRepo struct {
	identities map[uuid.UUID]*identity.Identity
}

func newMockIdentityRepo() *mockIdentityRepo {
	return &mockIdentityRepo{identities: make(map[uuid.UUID]*identity.Identity)}
}

func (m *mockIdentityRepo) Create(ctx context.Context, i *identity.Identity) error {
	m.identities[i.ID] = i
	return nil
}

func (m *mockIdentityRepo) GetByID(ctx context.Context, id uuid.UUID) (*identity.Identity, error) {
	i, ok := m.identities[id]
	if !ok {
		return nil, identity.ErrNotFound
	}
	return i, nil
}

func (m *mockIdentityRepo) GetByKindAndIdentifier(ctx context.Context, kind identity.Kind, identifier string) (*identity.Identity, error) {
	for _, i := range m.identities {
		if i.Kind == kind && i.Identifier == identifier {
			return i, nil
		}
	}
	return nil, identity.ErrNotFound
}

func (m *mockIdentityRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*identity.Identity, error) {
	var list []*identity.Identity
	for _, i := range m.identities {
		if i.UserID == userID {
			list = append(list, i)
		}
	}
	return list, nil
}

func (m *mockIdentityRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	return nil
}

type mockUserRepo struct{}

func (m *mockUserRepo) Create(ctx context.Context, u *user.User) error { return nil }
func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	return nil, user.ErrNotFound
}

type mockPasskeyCredRepo struct{}

func (m *mockPasskeyCredRepo) Create(ctx context.Context, c *passkey.Credential) error { return nil }
func (m *mockPasskeyCredRepo) GetByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	return nil, passkey.ErrCredentialNotFound
}
func (m *mockPasskeyCredRepo) GetByID(ctx context.Context, id uuid.UUID) (*passkey.Credential, error) {
	return nil, passkey.ErrCredentialNotFound
}
func (m *mockPasskeyCredRepo) ListByIdentityID(ctx context.Context, identityID uuid.UUID) ([]*passkey.Credential, error) {
	return nil, nil
}
func (m *mockPasskeyCredRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*passkey.Credential, error) {
	return nil, nil
}
func (m *mockPasskeyCredRepo) UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsedAt time.Time) error {
	return nil
}
func (m *mockPasskeyCredRepo) DeleteByID(ctx context.Context, id uuid.UUID) error { return nil }

type mockChallengeRepo struct{}

func (m *mockChallengeRepo) Create(ctx context.Context, ch *passkey.Challenge) error { return nil }
func (m *mockChallengeRepo) ConsumeByID(ctx context.Context, id uuid.UUID) (*passkey.Challenge, error) {
	return nil, passkey.ErrChallengeNotFound
}
func (m *mockChallengeRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockDeviceRepo struct{}

func (m *mockDeviceRepo) Create(ctx context.Context, d *device.Device) error { return nil }
func (m *mockDeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	return nil, device.ErrNotFound
}
func (m *mockDeviceRepo) GetByHash(ctx context.Context, hash []byte) (*device.Device, error) {
	return nil, device.ErrNotFound
}
func (m *mockDeviceRepo) Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error {
	return nil
}
func (m *mockDeviceRepo) UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error {
	return nil
}
func (m *mockDeviceRepo) Revoke(ctx context.Context, id uuid.UUID) error { return nil }
func (m *mockDeviceRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	return nil, nil
}

type mockWebAuthnService struct{}

func (m *mockWebAuthnService) BeginRegistration(u *user.User, existingCreds []*passkey.Credential) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockWebAuthnService) FinishRegistration(u *user.User, existingCreds []*passkey.Credential, sessionData []byte, responsePayload []byte) (*passkey.VerifiedCredential, error) {
	return nil, nil
}
func (m *mockWebAuthnService) BeginLogin() ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockWebAuthnService) FinishLogin(ctx context.Context, sessionData []byte, responsePayload []byte, lookup passkey.UserLookupFunc) (*passkey.VerifiedCredential, *user.User, error) {
	return nil, nil, nil
}

type testLimiter struct {
	exceeded bool
}

func (l *testLimiter) Allow(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	if l.exceeded {
		return []ratelimit.Result{{Allowed: false}}, nil
	}
	return []ratelimit.Result{{Allowed: true}}, nil
}

func (l *testLimiter) Usage(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return nil, nil
}

func buildTestRouter(t *testing.T) (*Router, *auth.Usecase, *sessionUC.Usecase, *mockOTPRepo, *mockSessionRepo, *mockIdentityRepo, *testLimiter, crypto.KeyRing) {
	t.Helper()
	sessionRepo := newMockSessionRepo()
	auditRepo := &mockAuditRepo{}
	txMgr := &mockTxManager{}
	otpRepo := newMockOTPRepo()
	identRepo := newMockIdentityRepo()
	limiter := &testLimiter{}
	mailerMock := &mockMailer{}

	keyRing := crypto.KeyRing{
		CurrentKeyID: 1,
		Keys: map[uint16][]byte{
			1: []byte("01234567890123456789012345678901"),
		},
	}

	sessionSvc := sessionUC.NewUsecase(sessionRepo, auditRepo, txMgr, nil, 24*time.Hour)
	authSvc := auth.NewUsecase(
		&mockUserRepo{},
		identRepo,
		&mockPasskeyCredRepo{},
		&mockChallengeRepo{},
		&mockDeviceRepo{},
		auditRepo,
		sessionSvc,
		txMgr,
		&mockWebAuthnService{},
		limiter,
		nil,
		keyRing,
		otpRepo,
		mailerMock,
		keyRing,
		6,
		10*time.Minute,
		5,
	)

	router := NewRouter(1, 2, authSvc, sessionSvc)
	return router, authSvc, sessionSvc, otpRepo, sessionRepo, identRepo, limiter, keyRing
}
