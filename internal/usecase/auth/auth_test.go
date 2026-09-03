package auth

import (
	"context"
	"fmt"
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
	sessionUC "airlance.org/api/internal/usecase/session"
)

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
	var count int64
	for id, c := range m.codes {
		if c.ExpiresAt.Before(before) {
			delete(m.codes, id)
			count++
		}
	}
	return count, nil
}

type mockMailer struct {
	sent []mailer.Message
}

func (m *mockMailer) Send(ctx context.Context, msg mailer.Message) error {
	m.sent = append(m.sent, msg)
	return nil
}

type mockUserRepo struct {
	users map[uuid.UUID]*user.User
}

func (m *mockUserRepo) Create(ctx context.Context, u *user.User) error {
	m.users[u.ID] = u
	return nil
}

func (m *mockUserRepo) GetByID(ctx context.Context, id uuid.UUID) (*user.User, error) {
	u, ok := m.users[id]
	if !ok {
		return nil, user.ErrNotFound
	}
	return u, nil
}

type mockIdentityRepo struct {
	identities map[uuid.UUID]*identity.Identity
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
	var res []*identity.Identity
	for _, i := range m.identities {
		if i.UserID == userID {
			res = append(res, i)
		}
	}
	return res, nil
}

func (m *mockIdentityRepo) MarkVerified(ctx context.Context, id uuid.UUID) error {
	if i, ok := m.identities[id]; ok {
		i.Verified = true
	}
	return nil
}

type mockPasskeyRepo struct {
	creds map[uuid.UUID]*passkey.Credential
}

func (m *mockPasskeyRepo) Create(ctx context.Context, c *passkey.Credential) error {
	m.creds[c.ID] = c
	return nil
}

func (m *mockPasskeyRepo) GetByID(ctx context.Context, id uuid.UUID) (*passkey.Credential, error) {
	c, ok := m.creds[id]
	if !ok {
		return nil, passkey.ErrCredentialNotFound
	}
	return c, nil
}

func (m *mockPasskeyRepo) GetByCredentialID(ctx context.Context, credID []byte) (*passkey.Credential, error) {
	for _, c := range m.creds {
		if string(c.CredentialID) == string(credID) {
			return c, nil
		}
	}
	return nil, passkey.ErrCredentialNotFound
}

func (m *mockPasskeyRepo) ListByIdentityID(ctx context.Context, identID uuid.UUID) ([]*passkey.Credential, error) {
	var res []*passkey.Credential
	for _, c := range m.creds {
		if c.IdentityID == identID {
			res = append(res, c)
		}
	}
	return res, nil
}

func (m *mockPasskeyRepo) ListByUserID(ctx context.Context, userID uuid.UUID) ([]*passkey.Credential, error) {
	var res []*passkey.Credential
	for _, c := range m.creds {
		res = append(res, c)
	}
	return res, nil
}

func (m *mockPasskeyRepo) UpdateSignCount(ctx context.Context, id uuid.UUID, newCount uint32, lastUsed time.Time) error {
	if c, ok := m.creds[id]; ok {
		c.SignCount = newCount
		c.LastUsedAt = &lastUsed
		return nil
	}
	return passkey.ErrCredentialNotFound
}

func (m *mockPasskeyRepo) DeleteByID(ctx context.Context, id uuid.UUID) error {
	delete(m.creds, id)
	return nil
}

type mockChallengeRepo struct {
	challenges map[uuid.UUID]*passkey.Challenge
}

func (m *mockChallengeRepo) Create(ctx context.Context, ch *passkey.Challenge) error {
	m.challenges[ch.ID] = ch
	return nil
}

func (m *mockChallengeRepo) ConsumeByID(ctx context.Context, id uuid.UUID) (*passkey.Challenge, error) {
	ch, ok := m.challenges[id]
	if !ok {
		return nil, passkey.ErrChallengeNotFound
	}
	delete(m.challenges, id)
	return ch, nil
}

func (m *mockChallengeRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockDeviceRepo struct {
	devices map[uuid.UUID]*device.Device
}

func (m *mockDeviceRepo) Create(ctx context.Context, d *device.Device) error {
	m.devices[d.ID] = d
	return nil
}

func (m *mockDeviceRepo) GetByID(ctx context.Context, id uuid.UUID) (*device.Device, error) {
	d, ok := m.devices[id]
	if !ok {
		return nil, device.ErrNotFound
	}
	return d, nil
}

func (m *mockDeviceRepo) GetByHash(ctx context.Context, hash []byte) (*device.Device, error) {
	for _, d := range m.devices {
		if crypto.ConstantTimeCompareBytes(d.DeviceIdentifierHash, hash) {
			return d, nil
		}
	}
	return nil, device.ErrNotFound
}

func (m *mockDeviceRepo) Touch(ctx context.Context, id uuid.UUID, appVersion *string, lastSeen time.Time) error {
	if d, ok := m.devices[id]; ok {
		d.LastSeenAt = lastSeen
		d.LastAppVersion = appVersion
	}
	return nil
}

func (m *mockDeviceRepo) RebindUser(ctx context.Context, id uuid.UUID, userID uuid.UUID, appVersion *string, lastSeen time.Time) error {
	if d, ok := m.devices[id]; ok {
		d.UserID = userID
		d.LastSeenAt = lastSeen
		d.LastAppVersion = appVersion
		d.RevokedAt = nil
	}
	return nil
}

func (m *mockDeviceRepo) UpdateHash(ctx context.Context, id uuid.UUID, newHash []byte) error {
	if d, ok := m.devices[id]; ok {
		d.DeviceIdentifierHash = newHash
	}
	return nil
}

func (m *mockDeviceRepo) Revoke(ctx context.Context, id uuid.UUID) error {
	if d, ok := m.devices[id]; ok {
		now := time.Now()
		d.RevokedAt = &now
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

type mockTxManager struct{}

func (m *mockTxManager) WithTx(ctx context.Context, fn func(ctx context.Context) error) error {
	return fn(ctx)
}

type mockAuditRepo struct {
	events []*audit.Event
}

func (m *mockAuditRepo) Record(ctx context.Context, e *audit.Event) error {
	m.events = append(m.events, e)
	return nil
}

type mockSessionRepo struct {
	sessions map[string]*session.Session
}

func (m *mockSessionRepo) Create(ctx context.Context, s *session.Session) error {
	m.sessions[string(s.TokenHash)] = s
	return nil
}

func (m *mockSessionRepo) GetValid(ctx context.Context, tokenHash []byte) (*session.Session, error) {
	s, ok := m.sessions[string(tokenHash)]
	if !ok {
		return nil, session.ErrNotFound
	}
	return s, nil
}

func (m *mockSessionRepo) GetByID(ctx context.Context, id uuid.UUID) (*session.Session, error) {
	for _, s := range m.sessions {
		if s.ID == id {
			return s, nil
		}
	}
	return nil, session.ErrNotFound
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
	return nil
}

func (m *mockSessionRepo) RevokeAllForUser(ctx context.Context, userID uuid.UUID) error {
	return nil
}

func (m *mockSessionRepo) RevokeAllForDevice(ctx context.Context, deviceID uuid.UUID) error {
	return nil
}

func (m *mockSessionRepo) CleanupExpired(ctx context.Context, before time.Time) (int64, error) {
	return 0, nil
}

type mockWebAuthnService struct {
	shouldFail bool
}

func (m *mockWebAuthnService) BeginRegistration(u *user.User, existingCreds []*passkey.Credential) ([]byte, []byte, error) {
	return []byte(`{"publicKey":{"challenge":"signup_challenge"}}`), []byte(`{"challenge":"sd"}`), nil
}

func (m *mockWebAuthnService) FinishRegistration(u *user.User, existingCreds []*passkey.Credential, sessionData []byte, responsePayload []byte) (*passkey.VerifiedCredential, error) {
	if m.shouldFail {
		return nil, passkey.ErrVerificationFailed
	}
	return &passkey.VerifiedCredential{
		CredentialID: []byte("test-cred-id-12345"),
		PublicKey:    []byte("test-pubkey-bytes"),
		SignCount:    1,
		Transports:   []string{"internal"},
		AAGUID:       uuid.New(),
	}, nil
}

func (m *mockWebAuthnService) BeginLogin() ([]byte, []byte, error) {
	return []byte(`{"publicKey":{"challenge":"login_challenge"}}`), []byte(`{"challenge":"sd_login"}`), nil
}

func (m *mockWebAuthnService) FinishLogin(ctx context.Context, sessionData []byte, responsePayload []byte, lookup passkey.UserLookupFunc) (*passkey.VerifiedCredential, *user.User, error) {
	if m.shouldFail {
		return nil, nil, passkey.ErrVerificationFailed
	}
	u, _, err := lookup(ctx, []byte("test-cred-id-12345"), nil)
	if err != nil {
		return nil, nil, err
	}
	return &passkey.VerifiedCredential{
		CredentialID: []byte("test-cred-id-12345"),
		SignCount:    2,
	}, u, nil
}

type mockLimiter struct {
	allow bool
}

func (m *mockLimiter) Allow(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return []ratelimit.Result{{Allowed: m.allow}}, nil
}

func (m *mockLimiter) Usage(ctx context.Context, key string, limits []ratelimit.Limit) ([]ratelimit.Result, error) {
	return []ratelimit.Result{{Allowed: m.allow}}, nil
}

func TestAuthUsecase_SignupAndLoginFlow(t *testing.T) {
	userRepo := &mockUserRepo{users: make(map[uuid.UUID]*user.User)}
	identityRepo := &mockIdentityRepo{identities: make(map[uuid.UUID]*identity.Identity)}
	passkeyRepo := &mockPasskeyRepo{creds: make(map[uuid.UUID]*passkey.Credential)}
	challengeRepo := &mockChallengeRepo{challenges: make(map[uuid.UUID]*passkey.Challenge)}
	deviceRepo := &mockDeviceRepo{devices: make(map[uuid.UUID]*device.Device)}
	auditRepo := &mockAuditRepo{}
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*session.Session)}
	txMgr := &mockTxManager{}
	webAuthnSvc := &mockWebAuthnService{}
	limiter := &mockLimiter{allow: true}

	sessionUC := sessionUC.NewUsecase(sessionRepo, auditRepo, txMgr, nil, 24*time.Hour)

	keyRing := crypto.KeyRing{
		CurrentKeyID: 1,
		Keys: map[uint16][]byte{
			1: []byte("01234567890123456789012345678901"),
		},
	}

	otpRepo := newMockOTPRepo()
	mailerMock := &mockMailer{}

	uc := NewUsecase(userRepo, identityRepo, passkeyRepo, challengeRepo, deviceRepo, auditRepo, sessionUC, txMgr, webAuthnSvc, limiter, nil, keyRing, otpRepo, mailerMock, keyRing, 6, 10*time.Minute, 5)

	ctx := context.Background()

	// 1. Begin Signup
	signupOpts, err := uc.BeginSignup(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected BeginSignup error: %v", err)
	}
	if signupOpts.ChallengeID == uuid.Nil {
		t.Fatalf("expected non-nil challenge ID")
	}

	// 2. Finish Signup
	res, err := uc.FinishSignup(ctx, signupOpts.ChallengeID, []byte(`{}`), "device-123", "ios", nil, "127.0.0.1", "test-agent", "req-1")
	if err != nil {
		t.Fatalf("unexpected FinishSignup error: %v", err)
	}
	if res.User == nil || res.Token == "" || !res.IsNewUser {
		t.Fatalf("expected valid signup result")
	}

	creds, err := uc.ListCredentials(ctx, res.User.ID)
	if err != nil {
		t.Fatalf("unexpected ListCredentials error: %v", err)
	}
	if len(creds) != 1 {
		t.Fatalf("expected 1 credential, got %d", len(creds))
	}

	// 3. Begin Login
	loginOpts, err := uc.BeginLogin(ctx, "127.0.0.1")
	if err != nil {
		t.Fatalf("unexpected BeginLogin error: %v", err)
	}

	// 4. Finish Login
	loginRes, err := uc.FinishLogin(ctx, loginOpts.ChallengeID, []byte(`{}`), "device-123", "ios", nil, "127.0.0.1", "test-agent", "req-2")
	if err != nil {
		t.Fatalf("unexpected FinishLogin error: %v", err)
	}
	if loginRes.User.ID != res.User.ID || loginRes.Token == "" {
		t.Fatalf("expected matching login user ID")
	}
}

func TestUsecase_RequestAndVerifyLinkEmail(t *testing.T) {
	userRepo := &mockUserRepo{users: make(map[uuid.UUID]*user.User)}
	identityRepo := &mockIdentityRepo{identities: make(map[uuid.UUID]*identity.Identity)}
	passkeyRepo := &mockPasskeyRepo{creds: make(map[uuid.UUID]*passkey.Credential)}
	challengeRepo := &mockChallengeRepo{challenges: make(map[uuid.UUID]*passkey.Challenge)}
	deviceRepo := &mockDeviceRepo{devices: make(map[uuid.UUID]*device.Device)}
	auditRepo := &mockAuditRepo{}
	sessionRepo := &mockSessionRepo{sessions: make(map[string]*session.Session)}
	txMgr := &mockTxManager{}
	webAuthnSvc := &mockWebAuthnService{}
	limiter := &mockLimiter{allow: true}
	sessionUC := sessionUC.NewUsecase(sessionRepo, auditRepo, txMgr, nil, 24*time.Hour)
	keyRing := crypto.KeyRing{
		CurrentKeyID: 1,
		Keys: map[uint16][]byte{
			1: []byte("01234567890123456789012345678901"),
		},
	}
	otpRepo := newMockOTPRepo()
	mailerMock := &mockMailer{}

	uc := NewUsecase(userRepo, identityRepo, passkeyRepo, challengeRepo, deviceRepo, auditRepo, sessionUC, txMgr, webAuthnSvc, limiter, nil, keyRing, otpRepo, mailerMock, keyRing, 6, 10*time.Minute, 5)

	ctx := context.Background()
	user1 := uuid.New()
	user2 := uuid.New()

	// 1. Request link email
	reqRes, err := uc.RequestLinkEmail(ctx, user1, "User@Example.COM", "127.0.0.1")
	if err != nil {
		t.Fatalf("RequestLinkEmail failed: %v", err)
	}
	if reqRes == nil || reqRes.RequestID == uuid.Nil {
		t.Fatalf("expected valid OTPRequestResult")
	}
	if len(mailerMock.sent) != 1 {
		t.Fatalf("expected 1 email sent, got %d", len(mailerMock.sent))
	}

	// 2. Request again for same email -> invalidates first code
	reqRes2, err := uc.RequestLinkEmail(ctx, user1, "user@example.com", "127.0.0.1")
	if err != nil {
		t.Fatalf("second RequestLinkEmail failed: %v", err)
	}
	if len(mailerMock.sent) != 2 {
		t.Fatalf("expected 2 emails sent")
	}

	// 3. Verifying first requestID should fail (invalidated/consumed)
	_, err = uc.VerifyLinkEmail(ctx, user1, reqRes.RequestID, "123456", "127.0.0.1")
	if err != otp.ErrNotFound {
		t.Errorf("expected ErrNotFound for invalidated code, got %v", err)
	}

	// Get code from repo for reqRes2
	activeCode, ok := otpRepo.codes[reqRes2.RequestID]
	if !ok {
		t.Fatalf("active code not found in repo")
	}

	// 4. Verify with wrong code
	_, err = uc.VerifyLinkEmail(ctx, user1, reqRes2.RequestID, "000000", "127.0.0.1")
	if err != otp.ErrInvalidCode {
		t.Errorf("expected ErrInvalidCode, got %v", err)
	}

	// 5. Verify by different user
	// Find the actual 6 digit code that satisfies VerifyNumericCode
	var correctCode string
	for c := 0; c < 1000000; c++ {
		testCode := fmt.Sprintf("%06d", c)
		if crypto.VerifyNumericCode(testCode, activeCode.CodeHash, activeCode.KeyID, keyRing) {
			correctCode = testCode
			break
		}
	}
	if correctCode == "" {
		t.Fatalf("could not find matching code")
	}

	_, err = uc.VerifyLinkEmail(ctx, user2, reqRes2.RequestID, correctCode, "127.0.0.1")
	if err != otp.ErrNotFound {
		t.Errorf("expected ErrNotFound when verifying for different user, got %v", err)
	}

	// 6. Verify successfully for user1
	ident, err := uc.VerifyLinkEmail(ctx, user1, reqRes2.RequestID, correctCode, "127.0.0.1")
	if err != nil {
		t.Fatalf("VerifyLinkEmail failed: %v", err)
	}
	if ident == nil || ident.UserID != user1 || ident.Identifier != "user@example.com" || !ident.Verified {
		t.Errorf("unexpected identity: %+v", ident)
	}

	// 7. Requesting to link the same verified email by another user fails with ErrAlreadyLinked
	_, err = uc.RequestLinkEmail(ctx, user2, "user@example.com", "127.0.0.1")
	if err != otp.ErrAlreadyLinked {
		t.Errorf("expected ErrAlreadyLinked, got %v", err)
	}
}
