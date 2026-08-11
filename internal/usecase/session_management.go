package usecase

import (
	"context"

	"github.com/airlance/api/internal/domain/account"
	"github.com/airlance/api/internal/domain/session"
)

type SessionManagementUseCase struct {
	sessions session.Repository
	accounts account.Repository
}

func NewSessionManagementUseCase(sessions session.Repository, accounts account.Repository) *SessionManagementUseCase {
	return &SessionManagementUseCase{
		sessions: sessions,
		accounts: accounts,
	}
}

func (uc *SessionManagementUseCase) Logout(ctx context.Context, sessionID session.SessionID) error {
	return uc.sessions.Revoke(ctx, sessionID)
}

func (uc *SessionManagementUseCase) ListSessions(ctx context.Context, accountID account.AccountID) ([]session.Session, error) {
	return uc.sessions.ListActiveByAccount(ctx, accountID)
}

func (uc *SessionManagementUseCase) LogoutAll(ctx context.Context, accountID account.AccountID, currentSessionID session.SessionID, exceptCurrent bool) error {
	var except *session.SessionID
	if exceptCurrent {
		except = &currentSessionID
	}
	return uc.sessions.RevokeAllByAccount(ctx, accountID, except)
}

func (uc *SessionManagementUseCase) SetSessionTTL(ctx context.Context, accountID account.AccountID, months *int) error {
	if months != nil && *months != 3 && *months != 6 && *months != 12 {
		return account.ErrInvalidSessionTTL
	}
	return uc.accounts.SetSessionTTLMonths(ctx, accountID, months)
}
