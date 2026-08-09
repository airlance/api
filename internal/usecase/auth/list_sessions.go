package auth

import (
	"context"
	"fmt"

	"github.com/airlance/api/internal/domain/session"
)

type ListSessionsUseCase struct {
	sessions session.Repository
}

func NewListSessionsUseCase(sessions session.Repository) *ListSessionsUseCase {
	return &ListSessionsUseCase{sessions: sessions}
}

type ListSessionsInput struct {
	UserID           int32
	CurrentAuthKeyID uint64
}

type ListSessionsOutput struct {
	Sessions []*session.SessionView
}

func (uc *ListSessionsUseCase) Execute(ctx context.Context, in ListSessionsInput) (*ListSessionsOutput, error) {
	views, err := uc.sessions.ListActiveByUserID(ctx, in.UserID)
	if err != nil {
		return nil, fmt.Errorf("list sessions: %w", err)
	}
	return &ListSessionsOutput{Sessions: views}, nil
}
