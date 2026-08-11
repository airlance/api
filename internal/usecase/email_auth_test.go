package usecase_test

import (
	"context"
	"testing"
	"time"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/infrastructure/memory"
	"github.com/airlance/api/internal/usecase"
)

type mockAccountRepo struct {
	accounts map[string]account.Account
	byID     map[account.AccountID]account.Account
	nextID   uint64
}

func newMockAccountRepo() *mockAccountRepo {
	return &mockAccountRepo{
		accounts: make(map[string]account.Account),
		byID:     make(map[account.AccountID]account.Account),
		nextID:   1,
	}
}

func (m *mockAccountRepo) CreateAccount(ctx context.Context, email, firstName, lastName string) (account.Account, error) {
	acc := account.Account{
		ID:        account.AccountID(m.nextID),
		Email:     email,
		FirstName: firstName,
		LastName:  lastName,
		Confirmed: false,
		CreatedAt: time.Now(),
	}
	m.nextID++
	m.accounts[email] = acc
	m.byID[acc.ID] = acc
	return acc, nil
}

func (m *mockAccountRepo) FindByEmail(ctx context.Context, email string) (account.Account, error) {
	acc, ok := m.accounts[email]
	if !ok {
		return account.Account{}, account.ErrAccountNotFound
	}
	return acc, nil
}

func (m *mockAccountRepo) FindByID(ctx context.Context, id account.AccountID) (account.Account, error) {
	acc, ok := m.byID[id]
	if !ok {
		return account.Account{}, account.ErrAccountNotFound
	}
	return acc, nil
}

func (m *mockAccountRepo) ConfirmAccount(ctx context.Context, id account.AccountID) error {
	acc, ok := m.byID[id]
	if !ok {
		return account.ErrAccountNotFound
	}
	acc.Confirmed = true
	m.byID[id] = acc
	m.accounts[acc.Email] = acc
	return nil
}

func (m *mockAccountRepo) SetSessionTTLMonths(ctx context.Context, id account.AccountID, months *int) error {
	acc, ok := m.byID[id]
	if !ok {
		return account.ErrAccountNotFound
	}
	acc.SessionTTLMonths = months
	m.byID[id] = acc
	m.accounts[acc.Email] = acc
	return nil
}

type mockCodeRepo struct {
	codes map[account.AccountID][]byte
}

func newMockCodeRepo() *mockCodeRepo {
	return &mockCodeRepo{codes: make(map[account.AccountID][]byte)}
}

func (m *mockCodeRepo) SaveCode(ctx context.Context, accountID account.AccountID, codeHash []byte, expiresAt time.Time) error {
	m.codes[accountID] = codeHash
	return nil
}

func (m *mockCodeRepo) ConsumeCode(ctx context.Context, accountID account.AccountID, codeHash []byte) error {
	stored, ok := m.codes[accountID]
	if !ok {
		return account.ErrInvalidCode
	}
	_ = stored
	delete(m.codes, accountID)
	return nil
}

type mockIdentityRepo struct {
	byProviderUser map[string]authidentity.AuthIdentity
	nextID         uint64
}

func newMockIdentityRepo() *mockIdentityRepo {
	return &mockIdentityRepo{byProviderUser: make(map[string]authidentity.AuthIdentity), nextID: 1}
}

func (m *mockIdentityRepo) Create(ctx context.Context, identity authidentity.AuthIdentity) (authidentity.AuthIdentity, error) {
	identity.ID = authidentity.AuthIdentityID(m.nextID)
	m.nextID++
	key := string(identity.Provider) + ":" + identity.ProviderUserID
	m.byProviderUser[key] = identity
	return identity, nil
}

func (m *mockIdentityRepo) FindByProviderUserID(ctx context.Context, provider authidentity.Provider, providerUserID string) (authidentity.AuthIdentity, error) {
	key := string(provider) + ":" + providerUserID
	id, ok := m.byProviderUser[key]
	if !ok {
		return authidentity.AuthIdentity{}, authidentity.ErrIdentityNotFound
	}
	return id, nil
}

func (m *mockIdentityRepo) FindByAccountAndProvider(ctx context.Context, accountID account.AccountID, provider authidentity.Provider) (authidentity.AuthIdentity, error) {
	for _, id := range m.byProviderUser {
		if id.AccountID == accountID && id.Provider == provider {
			return id, nil
		}
	}
	return authidentity.AuthIdentity{}, authidentity.ErrIdentityNotFound
}

func (m *mockIdentityRepo) ListByAccount(ctx context.Context, accountID account.AccountID) ([]authidentity.AuthIdentity, error) {
	var res []authidentity.AuthIdentity
	for _, id := range m.byProviderUser {
		if id.AccountID == accountID {
			res = append(res, id)
		}
	}
	return res, nil
}

type mockDeviceRepo struct {
	devices map[device.DeviceID]device.Device
	nextID  uint64
}

func newMockDeviceRepo() *mockDeviceRepo {
	return &mockDeviceRepo{devices: make(map[device.DeviceID]device.Device), nextID: 1}
}

func (m *mockDeviceRepo) CreateDevice(ctx context.Context, dev device.Device) (device.Device, error) {
	dev.ID = device.DeviceID(m.nextID)
	m.nextID++
	m.devices[dev.ID] = dev
	return dev, nil
}

func (m *mockDeviceRepo) FindByPublicKey(ctx context.Context, publicKey []byte) (device.Device, error) {
	for _, d := range m.devices {
		if string(d.PublicKey) == string(publicKey) {
			return d, nil
		}
	}
	return device.Device{}, device.ErrDeviceNotFound
}

func (m *mockDeviceRepo) FindByFingerprint(ctx context.Context, accountID account.AccountID, fingerprint string) (device.Device, error) {
	for _, d := range m.devices {
		if d.AccountID == accountID && d.Fingerprint == fingerprint {
			return d, nil
		}
	}
	return device.Device{}, device.ErrDeviceNotFound
}

func (m *mockDeviceRepo) TouchLastSeen(ctx context.Context, id device.DeviceID) error {
	if d, ok := m.devices[id]; ok {
		d.LastSeenAt = time.Now()
		m.devices[id] = d
		return nil
	}
	return device.ErrDeviceNotFound
}

func (m *mockDeviceRepo) ListByAccount(ctx context.Context, accountID account.AccountID) ([]device.Device, error) {
	var res []device.Device
	for _, d := range m.devices {
		if d.AccountID == accountID {
			res = append(res, d)
		}
	}
	return res, nil
}

func (m *mockDeviceRepo) Revoke(ctx context.Context, id device.DeviceID) error {
	if d, ok := m.devices[id]; ok {
		now := time.Now()
		d.RevokedAt = &now
		m.devices[id] = d
		return nil
	}
	return device.ErrDeviceNotFound
}

func TestEmailAuthUseCase_RequestAndConfirm(t *testing.T) {
	accRepo := newMockAccountRepo()
	idRepo := newMockIdentityRepo()
	devRepo := newMockDeviceRepo()
	sessRepo := memory.NewSessionRepository()
	codeRepo := newMockCodeRepo()

	emailAuth := usecase.NewEmailAuthUseCase(accRepo, idRepo, devRepo, sessRepo, codeRepo, nil, nil)
	ctx := context.Background()

	err := emailAuth.RequestCode(ctx, usecase.RequestCodeRequest{
		Email:     "user@example.com",
		FirstName: "John",
		LastName:  "Doe",
	})
	if err != nil {
		t.Fatalf("RequestCode failed: %v", err)
	}

	acc, err := accRepo.FindByEmail(ctx, "user@example.com")
	if err != nil {
		t.Fatalf("FindByEmail failed: %v", err)
	}

	sess, err := emailAuth.ConfirmCode(ctx, usecase.ConfirmCodeRequest{
		AccountID: acc.ID,
		Code:      "123456",
		Device: usecase.DeviceInfo{
			Fingerprint: "fp123",
			DeviceName:  "Test Phone",
			Platform:    "ios",
		},
	})
	if err != nil {
		t.Fatalf("ConfirmCode failed: %v", err)
	}

	if sess.ID == "" {
		t.Fatal("expected non-empty session ID")
	}

	accUpdated, err := accRepo.FindByID(ctx, acc.ID)
	if err != nil || !accUpdated.Confirmed {
		t.Fatalf("account should be confirmed: %v", err)
	}

	_, err = idRepo.FindByProviderUserID(ctx, authidentity.ProviderEmail, "user@example.com")
	if err != nil {
		t.Fatalf("email auth identity should exist: %v", err)
	}
}
