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

type mockPasskeyCredRepo struct {
	creds     map[uuid.UUID]*passkey.Credential
	userCreds map[uuid.UUID][]*passkey.Credential
}

func (m *mockPasskeyCredRepo) Create(ctx context.Context, c *passkey.Credential) error {
	if m.creds == nil {
		m.creds = make(map[uuid.UUID]*passkey.Credential)
	}
	m.creds[c.ID] = c
	return nil
}
func (m *mockPasskeyCredRepo) GetByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	return nil, passkey.ErrCredentialNotFound
}
func (m *mockPasskeyCredRepo) GetByID(ctx context.Context, id uuid.UUID) (*passkey.Credential, error) {
	if m.creds != nil {
		if c, ok := m.creds[id]; ok {
			return c, nil
		}
	}
	return nil, passkey.ErrCredentialNotFound
}
func (m *mockPasskeyCredRepo) ListByIdentityID(ctx context.Context, identityID uuid.UUID) ([]*passkey.Credential, error) {
	return nil, nil
}
func (m *mockPasskeyCredRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*passkey.Credential, error) {
	if m.userCreds != nil {
		if list, ok := m.userCreds[userID]; ok {
			return list, nil
		}
	}
	var res []*passkey.Credential
	for _, c := range m.creds {
		res = append(res, c)
	}
	return res, nil
}
func (m *mockPasskeyCredRepo) UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsedAt time.Time) error {
	return nil
}
func (m *mockPasskeyCredRepo) DeleteByID(ctx context.Context, id uuid.UUID) error {
	if m.creds != nil {
		delete(m.creds, id)
	}
	return nil
}

type mockChallengeRepo struct{}

func (m *mockChallengeRepo) Create(ctx context.Context, ch *passkey.Challenge) error { return nil }
func (m *mockChallengeRepo) ConsumeByID(ctx context.Context, id uuid.UUID) (*passkey.Challenge, error) {
	return nil, passkey.ErrChallengeNotFound
}
func (m *mockChallengeRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockDeviceRepo struct {
	devices map[uuid.UUID]*device.Device
}

func (m *mockDeviceRepo) Create(ctx context.Context, d *device.Device) error {
	if m.devices == nil {
		m.devices = make(map[uuid.UUID]*device.Device)
	}
	m.devices[d.ID] = d
	return nil
}
func (m *mockDeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	if m.devices != nil {
		if d, ok := m.devices[id]; ok {
			return d, nil
		}
	}
	return nil, device.ErrNotFound
}
func (m *mockDeviceRepo) GetByHash(ctx context.Context, hash []byte) (*device.Device, error) {
	return nil, device.ErrNotFound
}
func (m *mockDeviceRepo) Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error {
	return nil
}
func (m *mockDeviceRepo) RebindUser(ctx context.Context, id uuid.UUID, userID uuid.UUID, appVersion *string, lastSeen time.Time) error {
	return nil
}
func (m *mockDeviceRepo) UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error {
	return nil
}
func (m *mockDeviceRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	if m.devices != nil {
		if d, ok := m.devices[id]; ok {
			now := time.Now()
			d.RevokedAt = &now
		}
	}
	return nil
}
func (m *mockDeviceRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*device.Device, error) {
	var res []*device.Device
	for _, d := range m.devices {
		if d.UserID == userID {
			res = append(res, d)
		}
	}
	return res, nil
}

type mockWebAuthnService struct{}

func (m *mockWebAuthnService) BeginRegistration(u *user.User, existingCreds []*passkey.Credential) ([]byte, []byte, error) {
	return nil, nil, nil
}
func (m *mockWebAuthnService) FinishRegistration(u *user.User, existingCreds []*passkey.Credential, sessionData []byte, responsePayload []byte) (*passkey.VerifiedCredential, error) {
	return nil, nil
}
func (m *mockWebAuthnService) BeginLogin() ([]byte, []byte, error) { return nil, nil, nil }
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

type testRouterHarness struct {
	router      *Router
	authSvc     *auth.Usecase
	sessionSvc  *sessionUC.Usecase
	otpRepo     *mockOTPRepo
	sessionRepo *mockSessionRepo
	identRepo   *mockIdentityRepo
	deviceRepo  *mockDeviceRepo
	passkeyRepo *mockPasskeyCredRepo
	limiter     *testLimiter
	keyRing     crypto.KeyRing
}

func buildTestRouterFull(t *testing.T) *testRouterHarness {
	t.Helper()
	sessionRepo := newMockSessionRepo()
	auditRepo := &mockAuditRepo{}
	txMgr := &mockTxManager{}
	otpRepo := newMockOTPRepo()
	identRepo := newMockIdentityRepo()
	deviceRepo := &mockDeviceRepo{devices: make(map[uuid.UUID]*device.Device)}
	passkeyRepo := &mockPasskeyCredRepo{creds: make(map[uuid.UUID]*passkey.Credential)}
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
		passkeyRepo,
		&mockChallengeRepo{},
		deviceRepo,
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
	return &testRouterHarness{
		router:      router,
		authSvc:     authSvc,
		sessionSvc:  sessionSvc,
		otpRepo:     otpRepo,
		sessionRepo: sessionRepo,
		identRepo:   identRepo,
		deviceRepo:  deviceRepo,
		passkeyRepo: passkeyRepo,
		limiter:     limiter,
		keyRing:     keyRing,
	}
}

func buildTestRouter(t *testing.T) (*Router, *auth.Usecase, *sessionUC.Usecase, *mockOTPRepo, *mockSessionRepo, *mockIdentityRepo, *testLimiter, crypto.KeyRing) {
	t.Helper()
	h := buildTestRouterFull(t)
	return h.router, h.authSvc, h.sessionSvc, h.otpRepo, h.sessionRepo, h.identRepo, h.limiter, h.keyRing
}
