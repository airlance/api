package auth

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/airlance/api/internal/domain/authidentity"
	"github.com/airlance/api/internal/domain/clientcontext"
	"github.com/airlance/api/internal/domain/session"
	"github.com/airlance/api/internal/domain/transaction"
	"github.com/airlance/api/internal/domain/user"
	"github.com/airlance/api/internal/domain/userdevice"
)

type LoginByGithubUseCase struct {
	tx         transaction.TxManager
	users      user.Repository
	identities authidentity.Repository
	devices    userdevice.Repository
	sessions   session.Repository
	cache      session.SessionCache
	now        func() time.Time
}

func NewLoginByGithubUseCase(
	tx transaction.TxManager,
	users user.Repository,
	identities authidentity.Repository,
	devices userdevice.Repository,
	sessions session.Repository,
	cache session.SessionCache,
) *LoginByGithubUseCase {
	return &LoginByGithubUseCase{
		tx:         tx,
		users:      users,
		identities: identities,
		devices:    devices,
		sessions:   sessions,
		cache:      cache,
		now:        time.Now,
	}
}

type LoginByGithubInput struct {
	GithubUserID   int64
	GithubEmail    string
	GithubFullName string
	ClientCtx      clientcontext.ClientContext
}

type LoginByGithubOutput struct {
	AuthKeyID    uint64
	UserID       int32
	ResumeSecret string
}

func (uc *LoginByGithubUseCase) Execute(ctx context.Context, in LoginByGithubInput) (*LoginByGithubOutput, error) {
	newAuthKeyID, err := generateAuthKeyID()
	if err != nil {
		return nil, err
	}
	resumeSecret, resumeSecretHash, err := generateResumeSecret()
	if err != nil {
		return nil, err
	}

	var out LoginByGithubOutput
	identifier := strconv.FormatInt(in.GithubUserID, 10)

	err = uc.tx.WithinTx(ctx, func(ctx context.Context) error {
		identity, err := uc.identities.GetByProviderIdentifier(ctx, authidentity.ProviderGitHub, identifier)

		var u *user.User

		switch {
		case errors.Is(err, authidentity.ErrNotFound):
			email := in.GithubEmail
			if email == "" {
				email = fmt.Sprintf("github-%d@users.noreply.internal", in.GithubUserID)
			}

			u, err = uc.users.GetOrCreateByEmail(ctx, email, in.GithubFullName)
			if err != nil {
				return fmt.Errorf("get or create user: %w", err)
			}

			identity = &authidentity.Identity{
				UserID:     u.ID,
				Provider:   authidentity.ProviderGitHub,
				Identifier: identifier,
			}
			if err := uc.identities.Create(ctx, identity); err != nil {
				return fmt.Errorf("create identity: %w", err)
			}

		case err != nil:
			return fmt.Errorf("lookup identity: %w", err)

		default:
			u, err = uc.users.GetByID(ctx, identity.UserID)
			if err != nil {
				return fmt.Errorf("load user for identity: %w", err)
			}
			if err := uc.identities.UpdateLastUsed(ctx, identity.ID, uc.now()); err != nil {
				return fmt.Errorf("update identity last used: %w", err)
			}
		}

		if !u.IsActive() {
			return ErrUserDeactivated
		}

		fingerprint := userdevice.ComputeFingerprint(in.ClientCtx)
		device, err := uc.devices.GetOrCreate(ctx, u.ID, fingerprint, in.ClientCtx)
		if err != nil {
			return fmt.Errorf("resolve device: %w", err)
		}

		sess := &session.Session{
			AuthKeyID:        newAuthKeyID,
			UserID:           u.ID,
			AuthIdentityID:   identity.ID,
			DeviceID:         &device.ID,
			IPAddress:        in.ClientCtx.IPAddress,
			UserAgent:        in.ClientCtx.UserAgent,
			ResumeSecretHash: resumeSecretHash,
		}
		if err := uc.sessions.Create(ctx, sess); err != nil {
			return fmt.Errorf("create session: %w", err)
		}

		out = LoginByGithubOutput{AuthKeyID: sess.AuthKeyID, UserID: u.ID, ResumeSecret: resumeSecret}
		return nil
	})
	if err != nil {
		return nil, err
	}

	if err := uc.cache.Set(ctx, out.AuthKeyID, session.CacheEntry{
		UserID: out.UserID,
	}); err != nil {
		return &out, fmt.Errorf("%w: %v", ErrCacheWarmupFailed, err)
	}

	return &out, nil
}
