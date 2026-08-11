package usecase

import (
	"context"
	"fmt"
	"strconv"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/airlance/api/internal/domain/device"
	"github.com/airlance/api/internal/domain/oauth"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/infrastructure/logger"
)

type GithubAuthUseCase struct {
	accounts   account.Repository
	identities authidentity.Repository
	devices    device.Repository
	sessions   session.Repository
	github     oauth.GithubClient
	notifier   device.NewDeviceNotifier
}

func NewGithubAuthUseCase(
	accounts account.Repository,
	identities authidentity.Repository,
	devices device.Repository,
	sessions session.Repository,
	github oauth.GithubClient,
	notifier device.NewDeviceNotifier,
) *GithubAuthUseCase {
	return &GithubAuthUseCase{
		accounts:   accounts,
		identities: identities,
		devices:    devices,
		sessions:   sessions,
		github:     github,
		notifier:   notifier,
	}
}

func (uc *GithubAuthUseCase) BeginAuth(ctx context.Context, state string) string {
	return uc.github.AuthCodeURL(state)
}

func (uc *GithubAuthUseCase) CompleteAuth(ctx context.Context, code string, deviceInfo DeviceInfo) (session.Session, error) {
	ghUser, err := uc.github.Exchange(ctx, code)
	if err != nil {
		return session.Session{}, fmt.Errorf("github auth: exchange code failed: %w", err)
	}

	providerUserID := strconv.FormatInt(ghUser.ID, 10)

	var targetAccountID account.AccountID
	var accountEmail string

	identity, err := uc.identities.FindByProviderUserID(ctx, authidentity.ProviderGithub, providerUserID)
	if err == nil {
		targetAccountID = identity.AccountID
		acc, err := uc.accounts.FindByID(ctx, targetAccountID)
		if err == nil {
			accountEmail = acc.Email
		}
	} else if err == authidentity.ErrIdentityNotFound {
		if ghUser.EmailVerified && ghUser.Email != "" {
			existingAcc, err := uc.accounts.FindByEmail(ctx, ghUser.Email)
			if err == nil && existingAcc.Confirmed {
				targetAccountID = existingAcc.ID
				accountEmail = existingAcc.Email
			}
		}

		if targetAccountID == 0 {
			email := ghUser.Email
			if email == "" {
				email = fmt.Sprintf("%s@users.noreply.github.com", ghUser.Login)
			}
			newAcc, err := uc.accounts.CreateAccount(ctx, email, ghUser.Login, "")
			if err != nil {
				return session.Session{}, fmt.Errorf("github auth: create account failed: %w", err)
			}
			if err := uc.accounts.ConfirmAccount(ctx, newAcc.ID); err != nil {
				return session.Session{}, fmt.Errorf("github auth: confirm account failed: %w", err)
			}
			targetAccountID = newAcc.ID
			accountEmail = newAcc.Email
		}

		_, err = uc.identities.Create(ctx, authidentity.AuthIdentity{
			AccountID:      targetAccountID,
			Provider:       authidentity.ProviderGithub,
			ProviderUserID: providerUserID,
			ProviderEmail:  ghUser.Email,
			Metadata: map[string]any{
				"login":      ghUser.Login,
				"avatar_url": ghUser.AvatarURL,
			},
		})
		if err != nil {
			return session.Session{}, fmt.Errorf("github auth: create identity failed: %w", err)
		}
	} else {
		return session.Session{}, fmt.Errorf("github auth: find identity failed: %w", err)
	}

	dev, wasCreated, err := upsertDevice(ctx, uc.devices, targetAccountID, deviceInfo)
	if err != nil {
		return session.Session{}, fmt.Errorf("github auth: upsert device failed: %w", err)
	}

	if wasCreated && uc.notifier != nil && accountEmail != "" {
		bgCtx := context.Background()
		go func() {
			if err := uc.notifier.NotifyNewDevice(bgCtx, accountEmail, dev); err != nil {
				logger.FromContext(ctx).WithField("error", err).Warn("failed to send new device notification")
			}
		}()
	}

	sess, err := uc.sessions.CreateSession(ctx, dev.ID, targetAccountID)
	if err != nil {
		return session.Session{}, fmt.Errorf("github auth: create session failed: %w", err)
	}

	return sess, nil
}
